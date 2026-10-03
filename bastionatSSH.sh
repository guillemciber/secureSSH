#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Nom: bastionatSSH.sh
# Versió: 1.3.0
# Descripció:
#   Configura de manera interactiva l'accés SSH i la política de contrasenyes
#   d'un servidor Debian/Ubuntu. Abans d'aplicar res crea còpies de seguretat,
#   valida els fitxers temporals i demana una confirmació explícita.
#
#   Després de reiniciar SSH executa auditSSH.sh. Si l'auditoria detecta algun
#   resultat vermell, si falla l'escriptura o si el servei SSH no queda actiu,
#   restaura automàticament els fitxers anteriors i reinicia el servei.
#
# Ús:
#   sudo bash bastionatSSH.sh
#
# Requisits:
#   - Executar com a root.
#   - Tenir auditSSH.sh al mateix directori que aquest script.
#   - Sistema amb systemd i OpenSSH Server.
#   - libpam-pwquality; si falta, l'script ofereix instal·lar-lo.
#
# Fitxers gestionats:
#   /etc/ssh/sshd_config
#   /etc/login.defs
#   /etc/security/pwquality.conf
#
# Registres i còpies:
#   /var/log/bastionatSSH/
#   /var/backups/bastionatSSH/
# -----------------------------------------------------------------------------

# Si algú l'executa amb «sh», es torna a obrir automàticament amb Bash.
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"

set -Eeuo pipefail

# A Debian les eines administratives, com sshd, solen estar a /usr/sbin.
# Es defineix un PATH complet per evitar falsos errors de dependències.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

readonly SCRIPT_VERSION='1.3.0'
readonly SSHD_CONFIG='/etc/ssh/sshd_config'
readonly LOGIN_DEFS='/etc/login.defs'
readonly PWQUALITY_CONF='/etc/security/pwquality.conf'
readonly LOG_DIR='/var/log/bastionatSSH'
readonly BACKUP_ROOT='/var/backups/bastionatSSH'

readonly DEFAULT_SSH_PORT=2222
readonly DEFAULT_MAX_AUTH_TRIES=3
readonly DEFAULT_PASSWORD_AUTH='no'
readonly DEFAULT_ROOT_LOGIN='no'
readonly DEFAULT_PASS_MAX_DAYS=90
readonly DEFAULT_PASS_MIN_DAYS=1
readonly DEFAULT_PASS_WARN_AGE=7
readonly DEFAULT_MINLEN=12
readonly DEFAULT_MINCLASS=3

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly SCRIPT_DIR
readonly AUDIT_SCRIPT="$SCRIPT_DIR/auditSSH.sh"

TRANSACTION_ACTIVE=0
COMMITTED=0
SSH_RESTARTED=0
PWQUALITY_INSTALLED_NOW=0
BACKUP_DIR=''
WORK_DIR=''
SSH_SERVICE=''

if [[ $EUID -ne 0 ]]; then
    printf '✗ [NO VALIDAT] Cal executar aquest script com a root.\n' >&2
    printf 'Exemple: sudo bash %s\n' "$0" >&2
    exit 1
fi

umask 077
mkdir -p "$LOG_DIR" "$BACKUP_ROOT"
RUN_ID="$(date '+%Y%m%d-%H%M%S')-$$"
readonly RUN_ID
readonly LOG_FILE="$LOG_DIR/bastionatSSH-$RUN_ID.log"

# Tot el que apareix al terminal també queda desat al log.
if [[ -t 1 ]]; then TERMINAL_AMB_COLOR=1; else TERMINAL_AMB_COLOR=0; fi
exec > >(tee -a "$LOG_FILE") 2>&1
LOGGER_PID=$!
LOGGER_CLOSED=0

GREEN=$'\033[32m'
ORANGE=$'\033[38;5;208m'
RED=$'\033[31m'
CYAN=$'\033[36m'
BOLD=$'\033[1m'
RESET=$'\033[0m'
if (( ! TERMINAL_AMB_COLOR )) || [[ -n "${NO_COLOR:-}" ]]; then
    GREEN=''; ORANGE=''; RED=''; CYAN=''; BOLD=''; RESET=''
fi

correcte() { printf '%s✓ [VALIDAT]%s %s\n' "$GREEN" "$RESET" "$1"; }
avis()     { printf '%s⚠️ [AVÍS]%s %s\n' "$ORANGE" "$RESET" "$1"; }
error()    { printf '%s✗ [NO VALIDAT]%s %s\n' "$RED" "$RESET" "$1"; }
solucio()  { printf '%s🔧 [SOLUCIÓ]%s %s\n' "$ORANGE" "$RESET" "$1"; }
informacio() { printf '%sℹ️ [INFORMACIÓ]%s %s\n' "$CYAN" "$RESET" "$1"; }

seccio() {
    printf '\n\n============================================================\n%s\n============================================================\n' "$1"
}

resultat_sense_canvis() {
    local motiu="$1" proposta="${2:-}"
    seccio 'RESULTAT FINAL'
    error "$motiu"
    [[ -z "$proposta" ]] || solucio "$proposta"
    if (( PWQUALITY_INSTALLED_NOW )); then
        printf 'Canvis de bastionament aplicats: cap. No s’ha reiniciat SSH.\n'
        informacio 'El paquet libpam-pwquality instal·lat durant aquesta execució es manté instal·lat.'
    else
        printf 'Canvis aplicats: cap. No s’ha modificat cap fitxer ni s’ha reiniciat SSH.\n'
    fi
    printf 'Log: %s\n' "$LOG_FILE"
}

resultat_error_transaccio() {
    local motiu="$1"
    seccio 'RESULTAT FINAL'
    error "$motiu"
    printf 'Canvis acceptats: cap. La configuració es restaurarà automàticament.\n'
    printf 'Log: %s\n' "$LOG_FILE"
}

imprimeix_linia_auditoria() {
    local linia="$1"
    case "$linia" in
        *'[NO VALIDAT]'*) printf '%s%s%s\n' "$RED" "$linia" "$RESET" ;;
        *'[AVÍS]'*)      printf '%s%s%s\n' "$ORANGE" "$linia" "$RESET" ;;
        *'[VALIDAT]'*)   printf '%s%s%s\n' "$GREEN" "$linia" "$RESET" ;;
        '✗ No validats:'*) printf '%s%s%s\n' "$RED" "$linia" "$RESET" ;;
        '⚠️ Avisos:'*)     printf '%s%s%s\n' "$ORANGE" "$linia" "$RESET" ;;
        '✓ Validats:'*)   printf '%s%s%s\n' "$GREEN" "$linia" "$RESET" ;;
        *) printf '%s\n' "$linia" ;;
    esac
}

resultat_error_auditoria() {
    local fitxer_auditoria="$1" linia trobat=0
    seccio 'RESULTAT FINAL'
    while IFS= read -r linia; do
        if [[ "$linia" == *'[NO VALIDAT]'* ]]; then
            imprimeix_linia_auditoria "$linia"
            trobat=1
        fi
    done < "$fitxer_auditoria"
    (( trobat )) || error 'L’auditoria no ha finalitzat correctament.'
    printf 'Canvis acceptats: cap. La configuració es restaurarà automàticament.\n'
    printf 'Log: %s\n' "$LOG_FILE"
}

resultat_aplicat() {
    local fitxer_auditoria="$1" linia
    seccio 'RESULTAT FINAL'
    printf 'Canvis aplicats i estat final comprovat amb auditSSH.sh:\n\n'
    while IFS= read -r linia; do
        if [[ "$linia" == *'[VALIDAT]'* || "$linia" == *'[AVÍS]'* || "$linia" == *'[NO VALIDAT]'* ]]; then
            imprimeix_linia_auditoria "$linia"
        fi
    done < "$fitxer_auditoria"
    printf '\nResum de l’auditoria:\n'
    while IFS= read -r linia; do
        if [[ "$linia" == *'Validats:'* || "$linia" == *'Avisos:'* || "$linia" == *'No validats:'* ]]; then
            imprimeix_linia_auditoria "$linia"
        fi
    done < "$fitxer_auditoria"
    printf '\nServei SSH: %s (actiu)\n' "$SSH_SERVICE"
    printf 'Còpia de seguretat: %s\n' "$BACKUP_DIR"
    printf 'Log: %s\n' "$LOG_FILE"
}

# Tanca la canonada de sortida i espera que tee acabi. Això evita que l'script
# retorni el prompt abans que els missatges s'hagin mostrat i desat al log.
tanca_log() {
    (( LOGGER_CLOSED )) && return 0
    LOGGER_CLOSED=1
    exec 1>&- 2>&-
    wait "$LOGGER_PID" 2>/dev/null || true
}

neteja() {
    [[ -z "$WORK_DIR" || ! -d "$WORK_DIR" ]] || rm -rf -- "$WORK_DIR"
}

detecta_servei_ssh() {
    if systemctl cat ssh.service >/dev/null 2>&1; then
        SSH_SERVICE='ssh.service'
    elif systemctl cat sshd.service >/dev/null 2>&1; then
        SSH_SERVICE='sshd.service'
    else
        error 'No s’ha trobat cap unitat ssh.service ni sshd.service.'
        solucio 'Instal·la i inicia OpenSSH Server: sudo apt update && sudo apt install openssh-server && sudo systemctl enable --now ssh'
        return 1
    fi
}

reinicia_ssh() {
    systemctl restart "$SSH_SERVICE" && systemctl is-active --quiet "$SSH_SERVICE"
}

restaura_fitxer() {
    local original="$1" nom_backup="$2"
    if [[ -f "$BACKUP_DIR/$nom_backup.absent" ]]; then
        rm -f -- "$original"
    elif [[ -f "$BACKUP_DIR/$nom_backup" ]]; then
        cp -a -- "$BACKUP_DIR/$nom_backup" "$original"
    else
        error "No existeix la còpia necessària per restaurar $original."
        solucio "Revisa manualment les còpies disponibles a $BACKUP_DIR i restaura $original."
        return 1
    fi
}

rollback() {
    local motiu="$1" resultat=0
    trap - INT TERM
    set +e

    seccio 'Restauració automàtica'
    informacio "$motiu Es restauraran els fitxers des de $BACKUP_DIR."

    restaura_fitxer "$SSHD_CONFIG" 'sshd_config' || resultat=1
    restaura_fitxer "$LOGIN_DEFS" 'login.defs' || resultat=1
    restaura_fitxer "$PWQUALITY_CONF" 'pwquality.conf' || resultat=1

    if sshd -t -f "$SSHD_CONFIG"; then
        correcte 'La configuració SSH restaurada té una sintaxi correcta.'
    else
        error 'La configuració SSH restaurada no supera sshd -t.'
        solucio 'Executa sudo sshd -t per veure la directiva incorrecta. Si indica que falten claus de host, executa sudo ssh-keygen -A.'
        resultat=1
    fi

    if (( SSH_RESTARTED )); then
        if reinicia_ssh; then
            correcte "Servei $SSH_SERVICE reiniciat amb la configuració anterior."
        else
            error "No s’ha pogut reiniciar $SSH_SERVICE després de restaurar-lo."
            solucio "Consulta el servei amb: sudo systemctl status $SSH_SERVICE --no-pager -l"
            solucio "Consulta els darrers errors amb: sudo journalctl -u $SSH_SERVICE -n 50 --no-pager"
            resultat=1
        fi
    fi

    TRANSACTION_ACTIVE=0
    neteja

    if (( resultat == 0 )); then
        correcte 'Els canvis s’han desfet i s’ha recuperat la configuració anterior.'
        if (( PWQUALITY_INSTALLED_NOW )); then
            informacio 'El paquet libpam-pwquality instal·lat durant aquesta execució es manté instal·lat.'
        fi
    else
        error "La restauració requereix revisió manual. Consulta el log: $LOG_FILE"
    fi
    return "$resultat"
}

sortida_inesperada() {
    local codi=$?
    if (( TRANSACTION_ACTIVE && ! COMMITTED )); then
        resultat_error_transaccio "El procés ha acabat inesperadament (codi $codi)."
        rollback "El procés ha acabat inesperadament (codi $codi)." || true
    fi
    neteja
    trap - EXIT
    tanca_log
    exit "$codi"
}

interrupcio() {
    if (( TRANSACTION_ACTIVE && ! COMMITTED )); then
        resultat_error_transaccio 'El procés ha estat interromput.'
        rollback 'El procés ha estat interromput.' || true
    fi
    neteja
    exit 130
}

trap sortida_inesperada EXIT
trap interrupcio INT TERM

demana_enter() {
    local text="$1" defecte="$2" minim="$3" maxim="$4" resposta
    while true; do
        read -r -p "$text [$defecte]: " resposta
        resposta=${resposta:-$defecte}
        if [[ "$resposta" =~ ^[0-9]+$ ]] && (( 10#$resposta >= minim && 10#$resposta <= maxim )); then
            printf '%d' "$((10#$resposta))"
            return 0
        fi
        error "Introdueix un nombre enter entre $minim i $maxim." >&2
    done
}

demana_si_no() {
    local text="$1" defecte="$2" resposta
    local indicador='s/N'
    [[ "$defecte" == yes ]] && indicador='S/n'

    while true; do
        read -r -p "$text ($indicador): " resposta
        resposta=${resposta,,}
        if [[ -z "$resposta" ]]; then
            printf '%s' "$defecte"
            return 0
        fi
        case "$resposta" in
            s|si|sí|y|yes) printf 'yes'; return 0 ;;
            n|no)          printf 'no';  return 0 ;;
            *) error 'Respon «s» o «n».' >&2 ;;
        esac
    done
}

format_dies() {
    if [[ "$1" -eq 1 ]]; then printf '1 dia'; else printf '%s dies' "$1"; fi
}

estat_si_no() {
    local valor="$1" activat="$2" desactivat="$3"
    if [[ "$valor" == yes ]]; then printf '%s' "$activat"; else printf '%s' "$desactivat"; fi
}

confirma_aplicacio() {
    local resposta
    resposta=$(demana_si_no 'Vols aplicar els canvis i reiniciar SSH?' no)
    [[ "$resposta" == yes ]]
}

# Compta entrades de clau pública als authorized_keys estàndard de les llars
# dels usuaris. No compta claus de host, certificats CA, AuthorizedKeysCommand
# ni rutes personalitzades amb AuthorizedKeysFile.
compta_claus_autoritzades() {
    local total=0 fitxer recompte
    local _contrasenya _uid _gid _gecos llar _shell

    while IFS=: read -r _usuari _contrasenya _uid _gid _gecos llar _shell; do
        [[ "$llar" == /* ]] || continue
        for fitxer in "$llar/.ssh/authorized_keys" "$llar/.ssh/authorized_keys2"; do
            [[ -r "$fitxer" ]] || continue
            recompte=$(awk '
                /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
                /(ssh-(rsa|dss|ed25519)(-cert-v01@openssh\.com)?|ecdsa-sha2-[^[:space:]]+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-[^[:space:]]+)([[:space:]]|$)/ { n++ }
                END { print n + 0 }
            ' "$fitxer")
            total=$((total + recompte))
        done
    done < <(getent passwd)

    printf '%d' "$total"
}

pwquality_instal·lat() {
    local estat
    command -v dpkg-query >/dev/null 2>&1 || return 1
    estat=$(dpkg-query -W -f='${Status}' libpam-pwquality 2>/dev/null || true)
    [[ "$estat" == 'install ok installed' ]]
}

comprova_pwquality() {
    local resposta
    if pwquality_instal·lat; then
        correcte 'Paquet de qualitat de contrasenyes instal·lat (libpam-pwquality).'
        return 0
    fi

    avis 'El paquet libpam-pwquality no està instal·lat; els valors minlen i minclass no s’aplicarien realment.'
    resposta=$(demana_si_no 'Vols instal·lar ara libpam-pwquality?' no)
    if [[ "$resposta" != yes ]]; then
        resultat_sense_canvis 'No es pot aplicar la política de qualitat de contrasenyes sense libpam-pwquality.' \
            'Instal·la’l amb: sudo apt update && sudo apt install libpam-pwquality'
        return 1
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        resultat_sense_canvis 'No s’ha trobat apt-get i no es pot instal·lar libpam-pwquality.' \
            'Instal·la manualment libpam-pwquality amb el gestor de paquets del sistema.'
        return 1
    fi

    informacio 'S’instal·larà libpam-pwquality. Aquesta instal·lació es mantindrà encara que després es cancel·li o es restauri el bastionament.'
    if ! apt-get update || ! DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-pwquality; then
        resultat_sense_canvis 'No s’ha pogut instal·lar libpam-pwquality.' \
            'Revisa la connexió i els repositoris d’APT i executa: sudo apt update && sudo apt install libpam-pwquality'
        return 1
    fi

    if ! pwquality_instal·lat; then
        resultat_sense_canvis 'APT ha acabat, però libpam-pwquality no consta com a instal·lat.' \
            'Comprova el paquet amb: dpkg-query -W libpam-pwquality'
        return 1
    fi

    PWQUALITY_INSTALLED_NOW=1
    correcte 'Paquet libpam-pwquality instal·lat correctament.'
}

valor_login_defs() {
    awk -v key="$1" '$1 !~ /^#/ && $1 == key { value=$2 } END { if (value != "") print value }' "$2"
}

valor_pwquality() {
    awk -F= -v wanted="$1" '
        { line=$0; sub(/[[:space:]]*#.*/, "", line); n=split(line, p, "=")
          key=p[1]; gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
          if (key == wanted && n > 1) {
              value=p[2]; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
          }
        }
        END { if (value != "") print value }
    ' "$2"
}

# Elimina un bloc gestionat anteriorment i afegeix el nou al principi. En
# sshd_config preval la primera aparició d'una directiva, per això el bloc va
# abans de la resta del fitxer.
genera_sshd_config() {
    awk '
        /^# BEGIN BASTIONATSSH$/ { bloc=1; next }
        /^# END BASTIONATSSH$/   { bloc=0; next }
        bloc { next }
        /^[[:space:]]*Match[[:space:]]+/ { dins_match=1; print; next }
        !dins_match {
            linia=$0
            sub(/^[[:space:]]*/, "", linia)
            split(linia, p, /[[:space:]]+/)
            clau=tolower(p[1])
            if (clau == "port" || clau == "maxauthtries" ||
                clau == "passwordauthentication" ||
                clau == "kbdinteractiveauthentication" ||
                clau == "permitrootlogin") {
                print "# [bastionatSSH] Valor anterior: " $0
                next
            }
        }
        { print }
    ' "$SSHD_CONFIG" > "$WORK_DIR/sshd_config.base"

    {
        printf '%s\n' '# BEGIN BASTIONATSSH'
        printf 'Port %s\n' "$SSH_PORT"
        printf 'MaxAuthTries %s\n' "$MAX_AUTH_TRIES"
        printf 'PasswordAuthentication %s\n' "$PASSWORD_AUTH"
        printf 'KbdInteractiveAuthentication %s\n' "$PASSWORD_AUTH"
        printf 'PermitRootLogin %s\n' "$ROOT_LOGIN"
        printf '%s\n' '# END BASTIONATSSH' ''
        cat "$WORK_DIR/sshd_config.base"
    } > "$WORK_DIR/sshd_config"
}

# Conserva les línies antigues com a comentaris i escriu una sola definició
# activa de cada camp gestionat.
genera_login_defs() {
    awk '
        /^# BEGIN BASTIONATSSH$/ { bloc=1; next }
        /^# END BASTIONATSSH$/   { bloc=0; next }
        bloc { next }
        $1 !~ /^#/ && ($1 == "PASS_MAX_DAYS" || $1 == "PASS_MIN_DAYS" || $1 == "PASS_WARN_AGE") {
            print "# [bastionatSSH] Valor anterior: " $0
            next
        }
        { print }
    ' "$LOGIN_DEFS" > "$WORK_DIR/login.defs"

    {
        printf '\n%s\n' '# BEGIN BASTIONATSSH'
        printf 'PASS_MAX_DAYS\t%s\n' "$PASS_MAX_DAYS"
        printf 'PASS_MIN_DAYS\t%s\n' "$PASS_MIN_DAYS"
        printf 'PASS_WARN_AGE\t%s\n' "$PASS_WARN_AGE"
        printf '%s\n' '# END BASTIONATSSH'
    } >> "$WORK_DIR/login.defs"
}

genera_pwquality() {
    local origen="$PWQUALITY_CONF"
    [[ -f "$origen" ]] || origen='/dev/null'

    awk '
        /^# BEGIN BASTIONATSSH$/ { bloc=1; next }
        /^# END BASTIONATSSH$/   { bloc=0; next }
        bloc { next }
        /^[[:space:]]*#/ { print; next }
        {
            line=$0
            sub(/[[:space:]]*#.*/, "", line)
            split(line, p, "=")
            key=p[1]; gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            if (key == "minlen" || key == "minclass") {
                print "# [bastionatSSH] Valor anterior: " $0
                next
            }
            print
        }
    ' "$origen" > "$WORK_DIR/pwquality.conf"

    {
        printf '\n%s\n' '# BEGIN BASTIONATSSH'
        printf 'minlen = %s\n' "$MINLEN"
        printf 'minclass = %s\n' "$MINCLASS"
        printf '%s\n' '# END BASTIONATSSH'
    } >> "$WORK_DIR/pwquality.conf"
}

comprova_valor() {
    local nom="$1" esperat="$2" actual="$3"
    if [[ "$actual" == "$esperat" ]]; then
        correcte "$nom = $actual."
    else
        error "$nom: s’esperava «$esperat» però s’ha obtingut «${actual:-sense valor}»."
        case "$nom" in
            *efectiu)
                solucio 'Busca directives SSH duplicades amb: sudo grep -RniE "^(Port|MaxAuthTries|PasswordAuthentication|KbdInteractiveAuthentication|PermitRootLogin)" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/'
                ;;
            PASS_*)
                solucio 'Revisa les definicions actives amb: grep -nE "^[[:space:]]*PASS_(MAX_DAYS|MIN_DAYS|WARN_AGE)" /etc/login.defs'
                ;;
            minlen*|minclass*)
                solucio 'Revisa les definicions actives amb: grep -nE "^[[:space:]]*(minlen|minclass)[[:space:]]*=" /etc/security/pwquality.conf'
                ;;
        esac
        return 1
    fi
}

valida_fitxers_temporals() {
    local efectiva ports_efectius

    if sshd -t -f "$WORK_DIR/sshd_config"; then
        correcte 'Sintaxi de sshd_config correcta (sshd -t).'
    else
        error 'La configuració temporal de SSH no supera sshd -t.'
        solucio 'Revisa el detall mostrat per sshd. Si indica que falten claus de host, executa sudo ssh-keygen -A.'
        return 1
    fi

    efectiva=$(sshd -T -f "$WORK_DIR/sshd_config") || {
        error 'No s’ha pogut calcular la configuració SSH efectiva.'
        solucio 'Executa sudo sshd -T per obtenir el missatge complet i revisa /etc/ssh/sshd_config i /etc/ssh/sshd_config.d/.'
        return 1
    }

    ports_efectius=$(awk '$1 == "port" && !vist[$2]++ {
        if (ports != "") ports=ports "," $2; else ports=$2
    } END { print ports }' <<< "$efectiva")
    comprova_valor 'Port SSH efectiu' "$SSH_PORT" "$ports_efectius" || return 1
    comprova_valor 'Màxim d’intents efectiu' "$MAX_AUTH_TRIES" "$(awk '$1 == "maxauthtries" { print $2; exit }' <<< "$efectiva")" || return 1
    comprova_valor 'PasswordAuthentication efectiu' "$PASSWORD_AUTH" "$(awk '$1 == "passwordauthentication" { print $2; exit }' <<< "$efectiva")" || return 1
    comprova_valor 'KbdInteractiveAuthentication efectiu' "$PASSWORD_AUTH" "$(awk '$1 == "kbdinteractiveauthentication" { print $2; exit }' <<< "$efectiva")" || return 1
    comprova_valor 'PermitRootLogin efectiu' "$ROOT_LOGIN" "$(awk '$1 == "permitrootlogin" { print $2; exit }' <<< "$efectiva")" || return 1

    comprova_valor 'PASS_MAX_DAYS escrit' "$PASS_MAX_DAYS" "$(valor_login_defs PASS_MAX_DAYS "$WORK_DIR/login.defs")" || return 1
    comprova_valor 'PASS_MIN_DAYS escrit' "$PASS_MIN_DAYS" "$(valor_login_defs PASS_MIN_DAYS "$WORK_DIR/login.defs")" || return 1
    comprova_valor 'PASS_WARN_AGE escrit' "$PASS_WARN_AGE" "$(valor_login_defs PASS_WARN_AGE "$WORK_DIR/login.defs")" || return 1
    comprova_valor 'minlen escrit' "$MINLEN" "$(valor_pwquality minlen "$WORK_DIR/pwquality.conf")" || return 1
    comprova_valor 'minclass escrit' "$MINCLASS" "$(valor_pwquality minclass "$WORK_DIR/pwquality.conf")" || return 1
}

copia_seguretat() {
    local original="$1" nom_backup="$2"
    if [[ -e "$original" ]]; then
        cp -a -- "$original" "$BACKUP_DIR/$nom_backup"
    else
        : > "$BACKUP_DIR/$nom_backup.absent"
    fi
}

aplica_fitxers() {
    install -o root -g root -m 0644 "$WORK_DIR/sshd_config" "$SSHD_CONFIG"
    install -o root -g root -m 0644 "$WORK_DIR/login.defs" "$LOGIN_DEFS"
    install -d -o root -g root -m 0755 "$(dirname -- "$PWQUALITY_CONF")"
    install -o root -g root -m 0644 "$WORK_DIR/pwquality.conf" "$PWQUALITY_CONF"
}

seccio "BASTIONAT SSH — versió $SCRIPT_VERSION"
printf 'Log d’aquesta execució: %s\n' "$LOG_FILE"

for ordre in sshd systemctl awk install cp tee mktemp getent; do
    if ! command -v "$ordre" >/dev/null 2>&1; then
        error "Falta l’ordre necessària: $ordre."
        case "$ordre" in
            sshd)
                solucio 'Instal·la OpenSSH Server: sudo apt update && sudo apt install openssh-server'
                ;;
            systemctl)
                solucio 'Aquest script necessita un sistema iniciat amb systemd, com una instal·lació normal de Debian.'
                ;;
            awk)
                solucio 'Instal·la awk: sudo apt update && sudo apt install mawk'
                ;;
            install|cp|tee|mktemp)
                solucio 'Instal·la les eines bàsiques: sudo apt update && sudo apt install coreutils'
                ;;
            getent)
                solucio 'Instal·la les eines de consulta d’usuaris: sudo apt update && sudo apt install libc-bin'
                ;;
        esac
        resultat_sense_canvis "Falta la dependència necessària: $ordre."
        exit 1
    fi
done

if [[ ! -r "$SSHD_CONFIG" ]]; then
    error "No es pot llegir $SSHD_CONFIG."
    solucio 'Instal·la o reinstal·la OpenSSH Server: sudo apt update && sudo apt install --reinstall openssh-server'
    resultat_sense_canvis "No es pot llegir $SSHD_CONFIG."
    exit 1
fi
if [[ ! -r "$LOGIN_DEFS" ]]; then
    error "No es pot llegir $LOGIN_DEFS."
    solucio 'Reinstal·la el paquet que proporciona login.defs: sudo apt update && sudo apt install --reinstall login'
    resultat_sense_canvis "No es pot llegir $LOGIN_DEFS."
    exit 1
fi
if [[ ! -r "$AUDIT_SCRIPT" ]]; then
    error "No s’ha trobat $AUDIT_SCRIPT."
    solucio 'Copia auditSSH.sh al mateix directori que bastionatSSH.sh i torna a executar-lo.'
    resultat_sense_canvis "No s’ha trobat $AUDIT_SCRIPT."
    exit 1
fi
if ! detecta_servei_ssh; then
    resultat_sense_canvis 'No s’ha trobat cap servei SSH gestionat per systemd.'
    exit 1
fi

seccio '1. Valors nous'
KEY_COUNT=$(compta_claus_autoritzades)
readonly KEY_COUNT
SSH_PORT=$(demana_enter 'Port d’escolta SSH' "$DEFAULT_SSH_PORT" 1 65535)
MAX_AUTH_TRIES=$(demana_enter 'Màxim d’intents d’autenticació' "$DEFAULT_MAX_AUTH_TRIES" 1 6)

if (( KEY_COUNT > 0 )); then
    correcte "Claus públiques autoritzades detectades = $KEY_COUNT."
else
    avis 'No s’ha detectat cap clau pública als authorized_keys estàndard. Si respons «n» a la pregunta següent, et podries quedar sense cap mètode d’accés SSH.'
fi
PASSWORD_AUTH=$(demana_si_no 'Permetre l’autenticació SSH amb contrasenya?' "$DEFAULT_PASSWORD_AUTH")
if (( KEY_COUNT == 0 )) && [[ "$PASSWORD_AUTH" == no ]]; then
    MOTIU_CLAUS='No es pot desactivar l’autenticació amb contrasenya perquè no s’ha detectat cap clau pública autoritzada.'
    resultat_sense_canvis "$MOTIU_CLAUS" 'Afegeix la clau pública d’un client al fitxer ~/.ssh/authorized_keys de l’usuari del servidor; pots fer-ho des del client amb ssh-copy-id.'
    exit 1
fi
ROOT_LOGIN=$(demana_si_no 'Permetre l’accés SSH directe de root?' "$DEFAULT_ROOT_LOGIN")

PASS_MAX_DAYS=$(demana_enter 'Temps màxim d’ús d’una contrasenya, en dies' "$DEFAULT_PASS_MAX_DAYS" 8 365)
PASS_MIN_DAYS=$(demana_enter 'Temps mínim entre canvis de contrasenya, en dies' "$DEFAULT_PASS_MIN_DAYS" 1 30)
PASS_WARN_AGE=$(demana_enter 'Avís abans que caduqui la contrasenya, en dies' "$DEFAULT_PASS_WARN_AGE" 1 90)

MINLEN=$(demana_enter 'Longitud mínima d’una contrasenya' "$DEFAULT_MINLEN" 8 64)
MINCLASS=$(demana_enter 'Classes de caràcters requerides' "$DEFAULT_MINCLASS" 2 4)

readonly SSH_PORT MAX_AUTH_TRIES PASSWORD_AUTH ROOT_LOGIN
readonly PASS_MAX_DAYS PASS_MIN_DAYS PASS_WARN_AGE MINLEN MINCLASS

seccio '2. Configuració seleccionada'
printf 'Port d’escolta SSH = %s (Port = %s)\n' "$SSH_PORT" "$SSH_PORT"
printf 'Màxim d’intents d’autenticació = %s (MaxAuthTries = %s)\n' "$MAX_AUTH_TRIES" "$MAX_AUTH_TRIES"
printf 'Autenticació amb contrasenya = %s (PasswordAuthentication = %s; KbdInteractiveAuthentication = %s)\n' "$(estat_si_no "$PASSWORD_AUTH" 'activada' 'desactivada')" "$PASSWORD_AUTH" "$PASSWORD_AUTH"
printf 'Accés SSH directe de root = %s (PermitRootLogin = %s)\n' "$(estat_si_no "$ROOT_LOGIN" 'habilitat' 'deshabilitat')" "$ROOT_LOGIN"
printf 'Temps màxim d’ús d’una contrasenya = %s (PASS_MAX_DAYS = %s)\n' "$(format_dies "$PASS_MAX_DAYS")" "$PASS_MAX_DAYS"
printf 'Temps mínim entre canvis = %s (PASS_MIN_DAYS = %s)\n' "$(format_dies "$PASS_MIN_DAYS")" "$PASS_MIN_DAYS"
printf 'Avís abans de caducar = %s (PASS_WARN_AGE = %s)\n' "$(format_dies "$PASS_WARN_AGE")" "$PASS_WARN_AGE"
printf 'Longitud mínima = %s caràcters (minlen = %s)\n' "$MINLEN" "$MINLEN"
printf 'Classes requerides = %s (minclass = %s)\n' "$MINCLASS" "$MINCLASS"

seccio '3. Validació prèvia'
if ! comprova_pwquality; then
    exit 1
fi

WORK_DIR=$(mktemp -d /tmp/bastionatSSH.XXXXXX)
genera_sshd_config
genera_login_defs
genera_pwquality

if ! valida_fitxers_temporals; then
    resultat_sense_canvis 'La validació prèvia dels fitxers temporals ha fallat.'
    exit 1
fi

avis 'En reiniciar SSH, la connexió actual es podria interrompre.'
if [[ "$SSH_PORT" != 22 ]]; then
    avis "Abans de continuar, comprova que el tallafoc permet el port TCP $SSH_PORT. Aquest script no modifica el tallafoc."
fi
avis "El resultat complet quedarà desat a $LOG_FILE."

if ! confirma_aplicacio; then
    seccio 'RESULTAT FINAL'
    avis 'OPERACIÓ CANCEL·LADA.'
    if (( PWQUALITY_INSTALLED_NOW )); then
        correcte 'No s’ha aplicat la configuració de bastionament ni s’ha reiniciat SSH.'
        informacio 'El paquet libpam-pwquality instal·lat durant aquesta execució es manté instal·lat.'
    else
        correcte 'No s’ha modificat cap fitxer ni s’ha reiniciat SSH.'
    fi
    printf 'Log: %s\n' "$LOG_FILE"
    exit 0
fi

BACKUP_DIR="$BACKUP_ROOT/$RUN_ID"
mkdir -p "$BACKUP_DIR"
copia_seguretat "$SSHD_CONFIG" 'sshd_config'
copia_seguretat "$LOGIN_DEFS" 'login.defs'
copia_seguretat "$PWQUALITY_CONF" 'pwquality.conf'
TRANSACTION_ACTIVE=1

seccio '4. Aplicació i comprovació del servei'
if ! aplica_fitxers; then
    solucio 'Comprova l’espai disponible amb df -h i que /etc no estigui muntat en mode de només lectura.'
    resultat_error_transaccio 'No s’han pogut escriure tots els fitxers de configuració.'
    rollback 'No s’han pogut escriure tots els fitxers de configuració.' || true
    exit 1
fi
correcte 'Fitxers de configuració escrits.'

if ! sshd -t -f "$SSHD_CONFIG"; then
    solucio 'Executa sudo sshd -t per identificar la directiva incorrecta. Si falten claus de host, executa sudo ssh-keygen -A.'
    resultat_error_transaccio 'La configuració SSH instal·lada no supera sshd -t.'
    rollback 'La configuració SSH instal·lada no supera sshd -t.' || true
    exit 1
fi
correcte 'Configuració SSH instal·lada validada amb sshd -t.'

SSH_RESTARTED=1
if ! reinicia_ssh; then
    solucio "Consulta el servei amb: sudo systemctl status $SSH_SERVICE --no-pager -l"
    solucio "Consulta els darrers errors amb: sudo journalctl -u $SSH_SERVICE -n 50 --no-pager"
    resultat_error_transaccio "El servei $SSH_SERVICE no ha quedat actiu després del reinici."
    rollback "El servei $SSH_SERVICE no ha quedat actiu després del reinici." || true
    exit 1
fi
correcte "Servei $SSH_SERVICE reiniciat i actiu."

if bash "$AUDIT_SCRIPT" > "$WORK_DIR/auditoria-final.txt" 2>&1; then
    AUDIT_RESULT=0
else
    AUDIT_RESULT=$?
fi

# auditSSH.sh retorna 0 si tot està validat, 2 si només hi ha avisos i 1 si hi
# ha algun resultat vermell. Els avisos taronja no impedeixen aplicar els canvis.
if [[ $AUDIT_RESULT -eq 0 || $AUDIT_RESULT -eq 2 ]]; then
    COMMITTED=1
    TRANSACTION_ACTIVE=0
    trap - INT TERM
    resultat_aplicat "$WORK_DIR/auditoria-final.txt"
    neteja
    exit 0
fi

MOTIU_AUDITORIA="L’auditoria final ha detectat almenys un resultat vermell o ha fallat (codi $AUDIT_RESULT)."
resultat_error_auditoria "$WORK_DIR/auditoria-final.txt"
rollback "$MOTIU_AUDITORIA" || true
exit 1
