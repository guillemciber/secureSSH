#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Auditoria local de SSH i política de contrasenyes.
# Versió: 1.1
# Ús: sudo bash auditSSH.sh
#
# Només consulta fitxers i sockets que ja estan oberts. No prova credencials,
# no obre connexions i no modifica la configuració ni els serveis.
#
# Llindars pràctics escollits per a aquesta auditoria (no són universals):
#   SSH: el port 22 no ha de continuar configurat ni escoltant.
#   MaxAuthTries: 1-3.
#   Rang verd: MaxAuthTries 1-3; PASS_MAX_DAYS 60-90; PASS_MIN_DAYS 1-7;
#              PASS_WARN_AGE 7-30; minlen 12-64; minclass 3-4.
#   Límits pràctics vermells: MaxAuthTries 1-6; PASS_MAX_DAYS 8-365;
#     PASS_MIN_DAYS 1-30; PASS_WARN_AGE 1-90; minlen 8-64; minclass 2-4.
#   Dins dels límits pràctics, però fora del rang verd: avís taronja.
#   Fora dels límits pràctics: vermell (massa feble, excessiu o invàlid).
#   minclass compta quatre grups: minúscules, majúscules, números i símbols.
#
# Orientat a Debian/Ubuntu: revisa sshd_config i sshd_config.d/*.conf, els
# authorized_keys de les llars d'usuaris, /etc/login.defs i pwquality.conf.
# login.defs afecta els valors inicials dels comptes nous; PAM pot sobreescriure
# opcions de pwquality.conf mitjançant arguments directes al mòdul.
# -----------------------------------------------------------------------------

export LC_ALL=C

# Criteris centralitzats: canvia aquests valors si el projecte adopta una altra política.
MAX_AUTH_TRIES_MAX=3
MAX_AUTH_TRIES_HARD_MAX=6
PASS_MAX_DAYS_MAX=90
PASS_MAX_DAYS_MIN=60
PASS_MAX_DAYS_HARD_MIN=8
PASS_MAX_DAYS_HARD_MAX=365
PASS_MIN_DAYS_MIN=1
PASS_MIN_DAYS_MAX=7
PASS_MIN_DAYS_HARD_MAX=30
PASS_WARN_AGE_MIN=7
PASS_WARN_AGE_MAX=30
PASS_WARN_AGE_HARD_MAX=90
PWQUALITY_MINLEN_MIN=12
PWQUALITY_MINLEN_MAX=64
PWQUALITY_MINLEN_HARD_MIN=8
PWQUALITY_MINCLASS_MIN=3
PWQUALITY_MINCLASS_MAX=4
PWQUALITY_MINCLASS_HARD_MIN=2

SSHD_CONFIG=/etc/ssh/sshd_config
SSHD_DROPIN_DIR=/etc/ssh/sshd_config.d
LOGIN_DEFS=/etc/login.defs
PWQUALITY_CONF=/etc/security/pwquality.conf

OK_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

# Els colors s'activen en un terminal i desapareixen quan es desa la sortida.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    GREEN=$'\033[32m'; ORANGE=$'\033[38;5;208m'; RED=$'\033[31m'; RESET=$'\033[0m'
else
    GREEN=''; ORANGE=''; RED=''; RESET=''
fi

validat() {
    OK_COUNT=$((OK_COUNT + 1))
    printf '%s✓ [VALIDAT]%s %s\n' "$GREEN" "$RESET" "$1"
}

avis() {
    WARN_COUNT=$((WARN_COUNT + 1))
    printf '%s⚠️ [AVÍS]%s %s\n' "$ORANGE" "$RESET" "$1"
}

no_validat() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf '%s✗ [NO VALIDAT]%s %s\n' "$RED" "$RESET" "$1"
}

seccio() {
    printf '\n\n============================================================\n%s\n============================================================\n' "$1"
}

es_enter() {
    [[ "$1" =~ ^-?[0-9]+$ ]]
}

# Fa concordar el nom de la unitat amb el valor (1 dia, 2 dies; 1 classe...).
format_valor() {
    local valor="$1" unitat="$2"
    case "$unitat:$valor" in
        dies:1) printf '1 dia' ;;
        caràcters:1) printf '1 caràcter' ;;
        classes:1) printf '1 classe' ;;
        *)
            if [[ -n "$unitat" ]]; then printf '%s %s' "$valor" "$unitat"
            else printf '%s' "$valor"
            fi
            ;;
    esac
}

# Llegeix l'última definició activa de login.defs (directiva i valor separats per espais).
login_value() {
    [[ -r "$LOGIN_DEFS" ]] || return 0
    awk -v key="$1" '$1 !~ /^#/ && $1 == key { value=$2 } END { if (value != "") print value }' "$LOGIN_DEFS"
}

# Llegeix l'última definició activa de pwquality.conf (clau = valor).
pwquality_value() {
    [[ -r "$PWQUALITY_CONF" ]] || return 0
    awk -F= -v wanted="$1" '
        { line=$0; sub(/[[:space:]]*#.*/, "", line); fields=split(line, part, "=")
          key=part[1]; gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
          if (key == wanted && fields > 1) {
              value=part[2]; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
          }
        }
        END { if (value != "") print value }
    ' "$PWQUALITY_CONF"
}

# Si falta un valor, és un error; si existeix però queda fora del rang, és un avís taronja.
comprova_rang() {
    local nom="$1" clau="$2" valor="$3" dur_min="$4" dur_max="$5" segur_min="$6" segur_max="$7" recomanat="$8" unitat="$9" fitxer="${10}"
    local valor_visible
    valor_visible=$(format_valor "$valor" "$unitat")
    if [[ -z "$valor" ]]; then
        no_validat "$nom no està definit ($clau a $fitxer); recomanat: $recomanat."
    elif ! es_enter "$valor"; then
        no_validat "$nom = $valor ($clau = $valor); el valor no és un enter vàlid. Recomanat: $recomanat."
    elif (( valor < dur_min || valor > dur_max )); then
        no_validat "$nom = $valor_visible ($clau = $valor); valor no adequat, fora dels límits establerts. Recomanat: $recomanat."
    elif (( valor >= segur_min && valor <= segur_max )); then
        validat "$nom = $valor_visible ($clau = $valor)."
    else
        avis "$nom = $valor_visible ($clau = $valor); recomanat: $recomanat."
    fi
}

# sshd -T pot mostrar el valor predeterminat de MaxAuthTries encara que no
# s'hagi escrit. Aquesta cerca comprova que existeixi una directiva activa als
# fitxers globals estàndard; el valor que s'avalua continua sent el de sshd -T.
maxauthtries_definit() {
    local fitxers=("$SSHD_CONFIG")
    if compgen -G "$SSHD_DROPIN_DIR/*.conf" >/dev/null; then
        fitxers+=("$SSHD_DROPIN_DIR"/*.conf)
    fi
    grep -Eiq '^[[:space:]]*MaxAuthTries[[:space:]]+' "${fitxers[@]}" 2>/dev/null
}

if (( EUID != 0 )); then
    printf "%s⚠️ [AVÍS]%s Executa'l amb sudo per poder llegir els sockets i les claus de tots els usuaris.\n" "$ORANGE" "$RESET"
    printf 'Exemple: sudo bash %s\n' "$0"
    exit 1
fi

printf '%s\n' 'AUDITORIA LOCAL DE HARDENING — versió 1.1' 'Només lectura; sense proves de connexió.'

# sshd -T calcula la configuració efectiva local; no inicia ni contacta cap servei.
SSHD_OK=0
if command -v sshd >/dev/null 2>&1; then
    if SSHD_EFFECTIVE=$(sshd -T 2>&1); then
        SSHD_OK=1
    else
        no_validat "No es pot llegir la configuració efectiva amb sshd -T. Detall: ${SSHD_EFFECTIVE//$'\n'/ }"
    fi
else
    no_validat "No s'ha trobat sshd; no es poden revisar els controls SSH."
fi

seccio '1. Servei SSH'

if (( SSHD_OK )); then
    # Compara els ports efectius amb els sockets TCP que ara tenen un procés sshd escoltant.
    mapfile -t CONFIG_PORTS < <(awk '$1 == "port" { print $2 }' <<< "$SSHD_EFFECTIVE" | sort -nu)
    ((${#CONFIG_PORTS[@]})) || CONFIG_PORTS=(22)

    SS_OK=1
    if command -v ss >/dev/null 2>&1; then
        mapfile -t ACTIVE_PORTS < <(
            ss -H -ltnp 2>/dev/null | awk '
                index($0, "users:((\"sshd") > 0 {
                    port=$4; sub(/^.*:/, "", port)
                    if (port ~ /^[0-9]+$/) print port
                }
            ' | sort -nu
        )
    else
        SS_OK=0
        ACTIVE_PORTS=()
    fi

    CONFIG_TEXT=$(IFS=,; printf '%s' "${CONFIG_PORTS[*]}")
    ACTIVE_TEXT=$(IFS=,; printf '%s' "${ACTIVE_PORTS[*]}")
    CONFIG_HAS_22=0
    for port in "${CONFIG_PORTS[@]}"; do [[ "$port" == 22 ]] && CONFIG_HAS_22=1; done

    if (( ! SS_OK )); then
        no_validat "Port SSH configurat = $CONFIG_TEXT; port en execució = no verificable (falta l'ordre ss)."
    elif ((${#ACTIVE_PORTS[@]} == 0)); then
        if (( CONFIG_HAS_22 )); then
            no_validat "Port SSH configurat = $CONFIG_TEXT; port en execució = no detectat (cap socket de sshd)."
        else
            avis "Port SSH configurat = $CONFIG_TEXT; port en execució = no detectat. Comprova el servei i, si acabes de canviar-lo, reinicia SSH (Debian/Ubuntu: sudo systemctl restart ssh)."
        fi
    elif (( CONFIG_HAS_22 )); then
        if [[ "$CONFIG_TEXT" != "$ACTIVE_TEXT" ]]; then
            avis "Port SSH configurat = $CONFIG_TEXT; en execució = $ACTIVE_TEXT. El port 22 encara està configurat; recomanat = treure el port 22 i reiniciar SSH si acabes de canviar la configuració."
        else
            avis "Port SSH = 22 (configurat = 22; en execució = 22); recomanat = configurar un port diferent de 22."
        fi
    elif [[ "$CONFIG_TEXT" == "$ACTIVE_TEXT" ]]; then
        validat "Port SSH = $CONFIG_TEXT (configurat = $CONFIG_TEXT; en execució = $ACTIVE_TEXT)."
    else
        avis "Port SSH configurat = $CONFIG_TEXT; en execució = $ACTIVE_TEXT; recomanat = fer coincidir els valors reiniciant SSH (Debian/Ubuntu: sudo systemctl restart ssh)."
    fi

    MAX_AUTH_TRIES=$(awk '$1 == "maxauthtries" { print $2; exit }' <<< "$SSHD_EFFECTIVE")
    if maxauthtries_definit; then
        comprova_rang 'Màxim d’intents d’autenticació' MaxAuthTries "$MAX_AUTH_TRIES" 1 "$MAX_AUTH_TRIES_HARD_MAX" 1 "$MAX_AUTH_TRIES_MAX" "1-$MAX_AUTH_TRIES_MAX" '' 'sshd_config / sshd_config.d'
    else
        no_validat "Màxim d’intents d’autenticació no està definit (MaxAuthTries; valor efectiu = ${MAX_AUTH_TRIES:-desconegut}); recomanat = 1-$MAX_AUTH_TRIES_MAX."
    fi

    PASSWORD_AUTH=$(awk '$1 == "passwordauthentication" { print $2; exit }' <<< "$SSHD_EFFECTIVE")
    KBD_AUTH=$(awk '$1 == "kbdinteractiveauthentication" { print $2; exit }' <<< "$SSHD_EFFECTIVE")
    if [[ "$PASSWORD_AUTH" == no && "$KBD_AUTH" == no ]]; then
        validat 'Autenticació amb contrasenya = desactivada (PasswordAuthentication = no i KbdInteractiveAuthentication = no).'
    elif [[ "$PASSWORD_AUTH" != no ]]; then
        no_validat "Autenticació amb contrasenya = activada (PasswordAuthentication = ${PASSWORD_AUTH:-desconegut} i KbdInteractiveAuthentication = ${KBD_AUTH:-desconegut}); recomanat = no a tots dos paràmetres."
    else
        avis "Autenticació amb contrasenya = desactivada per PasswordAuthentication, però KbdInteractiveAuthentication = ${KBD_AUTH:-desconegut}; recomanat = no a tots dos paràmetres (revisa si PAM demana contrasenya)."
    fi

    ROOT_LOGIN=$(awk '$1 == "permitrootlogin" { print $2; exit }' <<< "$SSHD_EFFECTIVE")
    if [[ "$ROOT_LOGIN" == no ]]; then
        validat 'Accés SSH de root = deshabilitat (PermitRootLogin = no).'
    else
        no_validat "Accés SSH de root = no deshabilitat (PermitRootLogin = ${ROOT_LOGIN:-desconegut}); recomanat = no."
    fi
fi

# Compta entrades de clau pública als authorized_keys de les llars. No compta
# claus de host, rutes personalitzades, AuthorizedKeysCommand ni certificats CA.
KEY_COUNT=0
if command -v getent >/dev/null 2>&1; then
    while IFS=: read -r _ _ _ _ _ home _; do
        [[ "$home" == /* ]] || continue
        for file in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            [[ -r "$file" ]] || continue
            count=$(awk '
                /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
                /(ssh-(rsa|dss|ed25519)(-cert-v01@openssh\.com)?|ecdsa-sha2-[^[:space:]]+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-[^[:space:]]+)([[:space:]]|$)/ { n++ }
                END { print n + 0 }
            ' "$file")
            KEY_COUNT=$((KEY_COUNT + count))
        done
    done < <(getent passwd)
fi
if (( KEY_COUNT > 0 )); then
    validat "Entrades de clau pública autoritzades al servidor = $KEY_COUNT."
else
    no_validat 'Entrades de clau pública autoritzades al servidor = 0; recomanat = almenys 1.'
fi

seccio '2. Política de contrasenyes: /etc/login.defs'
comprova_rang 'Temps màxim d’ús d’una contrasenya' PASS_MAX_DAYS "$(login_value PASS_MAX_DAYS)" "$PASS_MAX_DAYS_HARD_MIN" "$PASS_MAX_DAYS_HARD_MAX" "$PASS_MAX_DAYS_MIN" "$PASS_MAX_DAYS_MAX" "$PASS_MAX_DAYS_MIN-$PASS_MAX_DAYS_MAX dies" dies "$LOGIN_DEFS"
comprova_rang 'Temps mínim entre canvis de contrasenya' PASS_MIN_DAYS "$(login_value PASS_MIN_DAYS)" "$PASS_MIN_DAYS_MIN" "$PASS_MIN_DAYS_HARD_MAX" "$PASS_MIN_DAYS_MIN" "$PASS_MIN_DAYS_MAX" "$PASS_MIN_DAYS_MIN-$PASS_MIN_DAYS_MAX dies" dies "$LOGIN_DEFS"
comprova_rang 'Avís abans que caduqui la contrasenya' PASS_WARN_AGE "$(login_value PASS_WARN_AGE)" 1 "$PASS_WARN_AGE_HARD_MAX" "$PASS_WARN_AGE_MIN" "$PASS_WARN_AGE_MAX" "$PASS_WARN_AGE_MIN-$PASS_WARN_AGE_MAX dies" dies "$LOGIN_DEFS"

seccio '3. Qualitat de contrasenyes: /etc/security/pwquality.conf'
comprova_rang 'Longitud mínima d’una contrasenya' minlen "$(pwquality_value minlen)" "$PWQUALITY_MINLEN_HARD_MIN" "$PWQUALITY_MINLEN_MAX" "$PWQUALITY_MINLEN_MIN" "$PWQUALITY_MINLEN_MAX" "$PWQUALITY_MINLEN_MIN-$PWQUALITY_MINLEN_MAX caràcters" caràcters "$PWQUALITY_CONF"
comprova_rang 'Classes de caràcters requerides' minclass "$(pwquality_value minclass)" "$PWQUALITY_MINCLASS_HARD_MIN" "$PWQUALITY_MINCLASS_MAX" "$PWQUALITY_MINCLASS_MIN" "$PWQUALITY_MINCLASS_MAX" "$PWQUALITY_MINCLASS_MIN-$PWQUALITY_MINCLASS_MAX classes" classes "$PWQUALITY_CONF"

seccio 'Resum'
printf '%s✓ Validats: %d%s\n' "$GREEN" "$OK_COUNT" "$RESET"
printf '%s⚠️ Avisos: %d%s\n' "$ORANGE" "$WARN_COUNT" "$RESET"
printf '%s✗ No validats: %d%s\n' "$RED" "$FAIL_COUNT" "$RESET"

# Codis de sortida: 0 = tot validat; 2 = avisos; 1 = algun control no validat.
if (( FAIL_COUNT > 0 )); then exit 1
elif (( WARN_COUNT > 0 )); then exit 2
else exit 0
fi
