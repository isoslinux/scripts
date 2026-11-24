#!/usr/bin/env bash
# =============================================================================
#  auditoria-seguridad.sh — Auditoría de seguridad para Ubuntu/Debian y Fedora/RHEL
#  Objetivo: detectar lo que permite a un atacante pasar de usuario normal a ROOT
#            (parches, kernel, configuración, permisos, servicios expuestos).
#
#  Uso:   sudo ./auditoria-seguridad.sh [opciones]
#     --kev        Cruza con el catálogo KEV de CISA (CVE explotados activamente)
#     --lynis      Ejecuta Lynis al final si está instalado (auditoría extra)
#     --sin-red    Omite consultas externas explícitas y usa caché local de DNF
#     --informe F  Guarda además el informe (sin colores) en el fichero F
#
#  No aplica cambios de configuración ni reinicia. Puede actualizar cachés.
#  Código de salida: 0 = sin hallazgos, 1 = avisos, 2 = fallos graves, 3 = error de uso
#
#  La sección 11 lleva una lista FIJA de vías de root publicadas (0-day y
#  explotadas). Caduca: revísala y actualiza DATOS_0DAY. Lo que se mantiene
#  solo al día es --kev. Un 0-day aún sin publicar no se puede detectar.
# =============================================================================
DATOS_0DAY="2026-11-24"   # fecha de la última revisión de la lista de la sección 11

set -uo pipefail
export LC_ALL=C

# ---------- Opciones ---------------------------------------------------------
USAR_KEV=0; USAR_LYNIS=0; SIN_RED=0; INFORME=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kev) USAR_KEV=1 ;;
    --lynis) USAR_LYNIS=1 ;;
    --sin-red) SIN_RED=1 ;;
    --informe)
      if [[ -z ${2:-} || $2 == --* ]]; then
        echo "Falta la ruta para --informe" >&2
        exit 3
      fi
      INFORME=$2
      shift
      ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; exit 3 ;;
  esac
  shift
done

if [[ -n "$INFORME" ]]; then
  umask 077
  set -o noclobber
  if ! { exec 3>"$INFORME"; }; then exit 3; fi
  set +o noclobber
  exec > >(tee -a /dev/fd/3) 2>&1
  exec 3>&-
fi

# ---------- Salida -----------------------------------------------------------
if [[ -t 1 && -z "$INFORME" ]]; then
  R=$'\e[31m'; V=$'\e[32m'; A=$'\e[33m'; B=$'\e[1m'; G=$'\e[2m'; F=$'\e[0m'
else R=""; V=""; A=""; B=""; G=""; F=""; fi

N_OK=0; N_AV=0; N_MAL=0
ok()   { echo "  ${V}[ OK ]${F} $*"; N_OK=$((N_OK+1)); }
av()   { echo "  ${A}[AVISO]${F} $*"; N_AV=$((N_AV+1)); }
mal()  { echo "  ${R}[ MAL ]${F} $*"; N_MAL=$((N_MAL+1)); }
info() { echo "  ${G}·${F} $*"; }
tit()  { echo; echo "${B}━━ $* ━━${F}"; }
tiene(){ command -v "$1" >/dev/null 2>&1; }

dnf_auditoria() {
  if (( SIN_RED )); then
    command dnf --cacheonly --setopt='*.skip_if_unavailable=False' "$@"
  else
    command dnf --setopt='*.skip_if_unavailable=False' "$@"
  fi
}

# ¿a >= b en orden de versiones?
vge() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$2" ]]; }

# Estado de una versión "X.Y.Z" frente a la lista de primeras versiones corregidas
# de cada serie ("6.12.91 6.18.33 7.1"). Solo vale donde NO se retroportan parches.
#   $1 versión  $2 primera versión afectada (o "")  $3 lista
#   → ok | vuln:<corregida> | unknown (serie no cubierta) | na (no afectada)
serie_estado() {
  local v=$1 min=$2 f fs serie
  [[ $v =~ ^[0-9]+\.[0-9]+$ ]] && v="$v.0"
  serie=${v%.*}
  [[ -n $min ]] && ! vge "$v" "$min" && { echo na; return; }
  for f in $3; do
    [[ $f =~ ^[0-9]+\.[0-9]+$ ]] && f="$f.0"
    fs=${f%.*}
    if [[ $fs == "$serie" ]]; then vge "$v" "$f" && echo ok || echo "vuln:$f"; return; fi
  done
  echo unknown
}

# ¿Queda parche sin aplicar para un CVE?  0 = sí, 1 = no, 2 = no se pudo consultar
dnf_cve_pend() { # dnf5 usa --cves=, dnf4 usa --cve
  local o
  o=$(dnf_auditoria -q updateinfo list --updates --cves="$1" 2>/dev/null) ||
    o=$(dnf_auditoria -q updateinfo list --updates --cve "$1" 2>/dev/null) || return 2
  grep -vE '^(Name|Type|ID)[[:space:]]' <<<"$o" | grep -q '[^[:space:]]'
}
pro_cve_pend() {
  local o rc
  o=$(pro fix "$1" --dry-run 2>&1); rc=$?
  if   grep -qi 'does not affect your system' <<<"$o"; then return 1
  elif grep -qiE 'install --only-upgrade|is not resolved|not available|investigating|reboot' <<<"$o"; then return 0
  elif (( rc == 0 )) && grep -qi 'is resolved' <<<"$o"; then return 1
  elif (( rc == 1 || rc == 2 )); then return 0
  else return 2; fi
}
cve_pend() {
  if [[ $FAM == rpm ]]; then dnf_cve_pend "$1"
  elif tiene pro; then pro_cve_pend "$1"
  else return 2; fi
}

if [[ $EUID -ne 0 ]]; then
  echo "${A}Ejecútalo con sudo: sin root faltarán comprobaciones.${F}"
fi

# ---------- Distribución -----------------------------------------------------
. /etc/os-release
case "${ID} ${ID_LIKE:-}" in
  *ubuntu*|*debian*)             FAM=deb ;;
  *fedora*|*rhel*|*centos*|*rocky*|*alma*) FAM=rpm ;;
  *) echo "Distribución no soportada: ${PRETTY_NAME}" >&2; exit 3 ;;
esac

echo "${B}Auditoría de seguridad${F} — $(hostname) — ${PRETTY_NAME} — $(date '+%Y-%m-%d %H:%M')"

# =============================================================================
tit "1. Sistema operativo y soporte"
# =============================================================================
if [[ $FAM == deb && $ID == ubuntu ]]; then
  if tiene ubuntu-distro-info; then
    if ubuntu-distro-info --supported | grep -qx "${VERSION_CODENAME}"; then
      ok "${PRETTY_NAME} sigue con soporte de seguridad"
    elif ubuntu-distro-info --supported-esm 2>/dev/null | grep -qx "${VERSION_CODENAME}"; then
      av "${PRETTY_NAME} solo tiene soporte ESM (Ubuntu Pro). Planifica actualizar"
    else
      mal "${PRETTY_NAME} ya NO recibe parches de seguridad"
    fi
  else info "Instala distro-info para comprobar si la versión sigue soportada"; fi
elif [[ $ID == fedora ]]; then
  # Fedora mantiene las dos últimas versiones (~13 meses cada una)
  info "Fedora ${VERSION_ID}: cada versión tiene soporte ~13 meses; asegúrate de no estar en una EOL"
fi

# =============================================================================
tit "2. Kernel (la vía de los 'root' de las noticias)"
# =============================================================================
EN_USO=$(uname -r)
if [[ $FAM == deb ]]; then
  ULTIMO=$(ls /boot/vmlinuz-* 2>/dev/null | sed 's|/boot/vmlinuz-||' | sort -V | tail -1)
else
  ULTIMO=$(rpm -q kernel kernel-core --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null \
           | grep -v 'not installed' | sort -Vu | tail -1)
fi
info "En uso: ${EN_USO}   |   Más reciente instalado: ${ULTIMO:-?}"

if [[ -z "$ULTIMO" ]]; then
  av "No encuentro kernels instalados (¿contenedor o kernel gestionado por el proveedor?)"
elif [[ "$EN_USO" != "$ULTIMO" ]]; then
  mal "Kernel nuevo instalado pero NO arrancado: los parches del kernel NO están activos → REINICIA"
else
  ok "Arrancado con el kernel más reciente instalado"
fi

if [[ -f /boot/vmlinuz-"$EN_USO" ]]; then
  DIAS=$(( ( $(date +%s) - $(stat -c %Y /boot/vmlinuz-"$EN_USO") ) / 86400 ))
  if   (( DIAS > 60 )); then mal "El kernel en uso tiene ~${DIAS} días"
  elif (( DIAS > 30 )); then av  "El kernel en uso tiene ~${DIAS} días"
  else ok "Kernel en uso de hace ~${DIAS} días"; fi
fi

# Reinicio pendiente por otras librerías
if [[ $FAM == deb ]]; then
  if [[ -f /var/run/reboot-required ]]; then
    mal "El sistema pide reinicio por: $(sort -u /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ')"
  else ok "No hay reinicio pendiente"; fi
  if tiene needrestart; then
    info "needrestart instalado: se consulta su versión sin ejecutar el programa"
  fi
else
  if dnf_auditoria needs-restarting -r >/dev/null 2>&1; then ok "No hay reinicio pendiente"
  else
    rc=$?; if (( rc == 1 )); then mal "El sistema pide reinicio (dnf needs-restarting -r)"
    else av "No pude comprobar el reinicio (instala dnf-plugins-core)"; fi
  fi
fi

# Live patching
if [[ $FAM == deb ]] && tiene canonical-livepatch; then
  canonical-livepatch status 2>/dev/null | grep -qi 'running: true' && ok "Canonical Livepatch activo"
elif [[ $FAM == rpm ]] && tiene kpatch; then
  kpatch list 2>/dev/null | grep -q 'Loaded patch' && ok "kpatch activo"
fi

# =============================================================================
tit "3. Parches de seguridad pendientes"
# =============================================================================
if [[ $FAM == deb ]]; then
  if ! (( SIN_RED )) && ! apt-get -o APT::Update::Error-Mode=any update -qq >/dev/null 2>&1; then
    av "No se pudieron actualizar todos los índices APT; parches pendientes sin verificar"
  elif (( SIN_RED )) && ! compgen -G '/var/lib/apt/lists/*_Packages*' >/dev/null; then
    av "No hay índices locales de paquetes APT; parches pendientes sin verificar"
  elif ! APT_UPGRADABLE=$(apt list --upgradable 2>/dev/null); then
    av "No se pudo consultar APT; parches pendientes sin verificar"
  else
    (( ! SIN_RED )) || info "APT: se usan índices locales que pueden estar desactualizados"
    SEG=$(awk -F/ '$0 ~ /-security/ {print $1}' <<<"$APT_UPGRADABLE")
    TOT=$(grep -c '\[upgradable' <<<"$APT_UPGRADABLE" || true)
    N=$(grep -c . <<<"$SEG" || true)
    if (( N > 0 )); then
      mal "$N paquetes con avisos de seguridad en APT (de $TOT actualizables):"
      head -30 <<<"$SEG" | sed 's/^/        /'
    else
      ok "APT no lista actualizaciones de seguridad en los índices consultados"
    fi
  fi

  if tiene unattended-upgrade && grep -qs '"1"' /etc/apt/apt.conf.d/20auto-upgrades; then
    ok "Actualizaciones automáticas de seguridad activas (unattended-upgrades)"
  else av "Actualizaciones automáticas de seguridad NO activas (unattended-upgrades)"; fi
else
  if ! (( SIN_RED )) && ! dnf_auditoria -q --refresh makecache >/dev/null 2>&1; then
    av "No se pudieron actualizar todos los metadatos DNF; avisos pendientes sin verificar"
  elif ! DNF_ADVISORIES=$(dnf_auditoria -q updateinfo list --updates --security 2>/dev/null); then
    av "No se pudo consultar DNF; avisos pendientes sin verificar"
  else
    (( ! SIN_RED )) || info "DNF: se usan metadatos locales que pueden estar desactualizados"
    SEG=$(awk 'NF && $1 !~ /^(Name|Type|ID)$/' <<<"$DNF_ADVISORIES")
    N=$(grep -c . <<<"$SEG" || true)
    if (( N > 0 )); then
      mal "$N entradas de avisos de seguridad pendientes en DNF:"
      head -30 <<<"$SEG" | sed 's/^/        /'
    else
      ok "DNF no lista avisos de seguridad en los metadatos consultados"
    fi
  fi

  if systemctl is-enabled dnf-automatic.timer dnf5-automatic.timer dnf-automatic-install.timer 2>/dev/null | grep -q enabled; then
    ok "dnf-automatic activo"
  else av "Actualizaciones automáticas NO activas (dnf-automatic)"; fi
fi

# =============================================================================
tit "4. Endurecimiento del kernel (frena exploits de escalada local)"
# =============================================================================
sysctl_chk() { # clave valor_bueno severidad explicación
  local v; v=$(sysctl -n "$1" 2>/dev/null) || { info "$1 no existe en este kernel"; return; }
  if [[ " $2 " == *" $v "* ]]; then ok "$1 = $v"
  elif [[ $3 == mal ]]; then mal "$1 = $v (recomendado: ${2// / o }) — $4"
  else av "$1 = $v (recomendado: ${2// / o }) — $4"; fi
}
sysctl_chk kernel.unprivileged_bpf_disabled "1 2" mal "BPF sin privilegios: origen de muchos root"
sysctl_chk kernel.kptr_restrict             "1 2" av  "oculta direcciones del kernel a exploits"
sysctl_chk kernel.dmesg_restrict            "1"   av  "usuarios normales leen el log del kernel"
sysctl_chk kernel.yama.ptrace_scope         "1 2 3" av "un usuario puede depurar procesos ajenos"
sysctl_chk kernel.randomize_va_space        "2"   mal "ASLR desactivado o parcial"
sysctl_chk fs.protected_symlinks            "1"   mal "ataques con enlaces simbólicos en /tmp"
sysctl_chk fs.protected_hardlinks           "1"   mal "ataques con enlaces duros"
sysctl_chk fs.protected_fifos               "1 2" av  "ataques con FIFOs en directorios compartidos"
sysctl_chk fs.protected_regular             "1 2" av  "ataques con ficheros en directorios compartidos"
sysctl_chk fs.suid_dumpable                 "0"   av  "programas SUID pueden volcar memoria"
sysctl_chk kernel.io_uring_disabled         "1 2" av  "io_uring: fuente frecuente de fallos del kernel (desactívalo si no lo usas)"
sysctl_chk kernel.sysrq                     "0 16 176" av "SysRq amplio habilitado"
sysctl_chk net.core.bpf_jit_harden          "2"   av  "endurecimiento del JIT de BPF"

# Espacios de nombres de usuario sin privilegios (base de muchos exploits recientes)
USERNS_LIBRE=1
if sysctl -n kernel.apparmor_restrict_unprivileged_userns >/dev/null 2>&1; then
  sysctl_chk kernel.apparmor_restrict_unprivileged_userns "1" av "user namespaces libres para cualquier usuario"
  [[ $(sysctl -n kernel.apparmor_restrict_unprivileged_userns) == 1 ]] && USERNS_LIBRE=0
elif sysctl -n kernel.unprivileged_userns_clone >/dev/null 2>&1; then
  sysctl_chk kernel.unprivileged_userns_clone "0" av "user namespaces libres (si no usas contenedores rootless, desactívalo)"
  [[ $(sysctl -n kernel.unprivileged_userns_clone) == 0 ]] && USERNS_LIBRE=0
else
  UNS=$(sysctl -n user.max_user_namespaces 2>/dev/null || echo "?")
  [[ "$UNS" == "0" ]] && USERNS_LIBRE=0
  if [[ "$UNS" != "0" ]]; then
    av "user.max_user_namespaces = $UNS: cualquier usuario crea user namespaces (necesario para Podman rootless; si no lo usas, pon 0)"
  else ok "user namespaces sin privilegios desactivados"; fi
fi

# Módulos peligrosos poco usados que se cargan solos
for m in dccp sctp rds tipc n_hdlc n_gsm cramfs freevxfs jffs2 hfs hfsplus udf firewire-core; do
  if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "${m//-/_}"; then
    av "Módulo $m cargado: si no lo usas, bloquéalo (install $m /bin/false)"
  fi
done

# Seguridad de arranque
if [[ -d /sys/firmware/efi ]] && tiene mokutil; then
  mokutil --sb-state 2>/dev/null | grep -qi enabled && ok "Secure Boot activo" || info "Secure Boot desactivado"
fi
if grep -qw lockdown /sys/kernel/security/lsm 2>/dev/null; then
  info "Kernel lockdown: $(cat /sys/kernel/security/lockdown 2>/dev/null)"
fi

# =============================================================================
tit "5. SELinux / AppArmor"
# =============================================================================
if tiene getenforce; then
  case "$(getenforce)" in
    Enforcing)  ok "SELinux en modo Enforcing" ;;
    Permissive) mal "SELinux en Permissive: no bloquea nada" ;;
    *)          mal "SELinux desactivado" ;;
  esac
elif tiene aa-status; then
  if aa-status --enabled 2>/dev/null; then
    E=$(aa-status 2>/dev/null | awk '/profiles are in enforce mode/ {print $1}')
    ok "AppArmor activo (${E:-?} perfiles en enforce)"
  else mal "AppArmor instalado pero NO activo"; fi
else
  mal "Ni SELinux ni AppArmor activos"
fi

# =============================================================================
tit "6. Usuarios, contraseñas y sudo"
# =============================================================================
UID0=$(awk -F: '$3==0 {print $1}' /etc/passwd | grep -vx root || true)
[[ -n "$UID0" ]] && mal "Otras cuentas con UID 0 (son root): $UID0" || ok "Solo 'root' tiene UID 0"

if [[ -r /etc/shadow ]]; then
  VACIAS=$(awk -F: '$2=="" {print $1}' /etc/shadow)
  [[ -n "$VACIAS" ]] && mal "Cuentas SIN contraseña: $VACIAS" || ok "Ninguna cuenta con contraseña vacía"
fi

echo "  Cuentas que pueden iniciar sesión:"
awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {printf "        %-16s uid=%-6s %s\n",$1,$3,$7}' /etc/passwd

ADM=$(getent group sudo wheel admin 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep . | sort -u | tr '\n' ' ')
info "Miembros de sudo/wheel: ${ADM:-ninguno}"

# Grupos que equivalen a root
for g in docker lxd libvirt disk; do
  M=$(getent group "$g" 2>/dev/null | cut -d: -f4)
  [[ -n "$M" ]] && av "Grupo '$g' (equivale a root): $M"
done

if [[ $EUID -eq 0 ]]; then
  NOPW=$(grep -rhsE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true)
  [[ -n "$NOPW" ]] && { av "Reglas sudo sin contraseña (NOPASSWD):"; printf '%s\n' "$NOPW" | sed 's/^/        /'; }
  grep -rhsE '^[^#].*!authenticate' /etc/sudoers /etc/sudoers.d/ >/dev/null && mal "sudo con !authenticate"
  # Ficheros sudoers con permisos incorrectos
  while read -r f; do mal "Permisos peligrosos en $f"; done < <(find /etc/sudoers /etc/sudoers.d -perm /022 2>/dev/null)
fi

# Versión de sudo (CVE-2025-32463 'chroot' afecta a 1.9.14–1.9.17)
if tiene sudo; then
  SV=$(sudo -V 2>/dev/null | awk 'NR==1{print $3}')
  if [[ -n "$SV" ]] && printf '1.9.14\n%s\n1.9.17\n' "${SV%%p*}" | sort -V -C 2>/dev/null; then
    av "sudo $SV: comprueba que tu distribución ya parcheó CVE-2025-32463 (opción --chroot)"
  else info "sudo versión $SV"; fi
fi

# =============================================================================
tit "7. SSH"
# =============================================================================
if tiene sshd; then
  # OpenSSH >= 10.5 imprime las claves con mayúsculas: normalizamos a minúsculas
  SSHC=$( (sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null) | awk '{ $1=tolower($1); print }')
  if ! grep -q '^permitrootlogin ' <<<"$SSHC"; then
    av "No pude leer la configuración efectiva de sshd (ejecuta: sudo sshd -t ; sudo sshd -T)"
  else
    v(){ printf '%s\n' "$SSHC" | awk -v k="$1" '$1==k {print $2; exit}'; }
    case "$(v permitrootlogin)" in
      no) ok "PermitRootLogin no" ;;
      prohibit-password|without-password) av "Root puede entrar con clave SSH (mejor: no)" ;;
      *) mal "Root puede entrar por SSH con contraseña" ;;
    esac
    [[ "$(v passwordauthentication)" == no ]] && ok "Solo autenticación por clave" \
      || av "PasswordAuthentication yes: expuesto a fuerza bruta"
    [[ "$(v permitemptypasswords)" == yes ]] && mal "PermitEmptyPasswords yes"
    [[ "$(v x11forwarding)" == yes ]] && av "X11Forwarding activado"
    MAXA=$(v maxauthtries); (( ${MAXA:-6} > 4 )) && av "MaxAuthTries = $MAXA (recomendado ≤ 4)"
    info "Puerto(s) SSH: $(printf '%s\n' "$SSHC" | awk '$1=="port"{print $2}' | tr '\n' ' ')"
  fi
  SV=$(ssh -V 2>&1 | grep -oE 'OpenSSH_[0-9.]+p?[0-9]*'); info "Versión: ${SV:-?}"
else info "sshd no instalado"; fi

# Protección contra fuerza bruta
if systemctl is-active fail2ban >/dev/null 2>&1; then ok "fail2ban activo"
elif systemctl is-active crowdsec >/dev/null 2>&1; then ok "CrowdSec activo"
else av "Sin fail2ban/CrowdSec contra fuerza bruta"; fi

# =============================================================================
tit "8. Red y servicios expuestos"
# =============================================================================
if systemctl is-active firewalld >/dev/null 2>&1; then
  ok "firewalld activo (zona por defecto: $(firewall-cmd --get-default-zone 2>/dev/null))"
elif tiene ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then ok "ufw activo"
elif tiene nft && nft list ruleset 2>/dev/null | grep -qE 'hook input.*policy drop'; then ok "nftables con política drop"
else mal "No detecto cortafuegos activo"; fi

if tiene ss; then
  echo "  Puertos escuchando en TODAS las interfaces (alcance por verificar):"
  ss -Htulpn 2>/dev/null | awk '$5 ~ /^(0\.0\.0\.0|\*|\[::\]):/ {
     split($5,a,":"); p=a[length(a)]; s=$7; gsub(/users:\(\("|".*/,"",s);
     printf "        %-4s %-6s %s\n",$1,p,s}' | sort -u -k2n
  # Servicios que no deberían estar abiertos al mundo
  while read -r l; do mal "Servicio sensible escuchando en todas las interfaces; confirma alcance: $l"; done < <(
    ss -Htlpn 2>/dev/null | awk '$4 ~ /^(0\.0\.0\.0|\*|\[::\]):/ {print $4}' \
    | grep -E ':(3306|5432|6379|27017|9200|11211|2375|2376|5984|8086|9000|11434)$')
fi

# =============================================================================
tit "9. Ficheros y permisos peligrosos"
# =============================================================================
if [[ $EUID -eq 0 ]]; then
  # Binarios SUID/SGID conocidos por permitir saltar a root si están mal (GTFOBins)
  PELIG="nmap vim vi find bash sh dash zsh python python3 perl ruby lua php node awk gawk less more nano cp mv tar zip env tee dd openssl wget curl socat nc ncat busybox docker git"
  SUIDS=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
  info "$(printf '%s\n' "$SUIDS" | grep -c .) binarios SUID/SGID en el sistema"
  for b in $PELIG; do
    while read -r f; do mal "SUID peligroso: $f"; done < <(printf '%s\n' "$SUIDS" | grep -E "/${b}$")
  done
  # SUID fuera de rutas del sistema
  while read -r f; do av "SUID/SGID fuera de rutas del sistema: $f"; done < <(
    printf '%s\n' "$SUIDS" | grep -vE '^/(usr/)?(s?bin|lib|lib64|libexec)/' | grep .)

  # Capabilities peligrosas
  if tiene getcap; then
    while read -r l; do av "Capability peligrosa: $l"; done < <(
      getcap -r / 2>/dev/null | grep -E 'cap_(setuid|setgid|sys_admin|sys_ptrace|dac_override|dac_read_search|sys_module)' \
      | grep -vE '^/usr/(bin/new[ug]idmap|libexec/sssd/)')
  fi

  # Ficheros críticos
  for f in /etc/passwd /etc/group; do (( 8#$(stat -c %a "$f") & 8#022 )) && mal "Permisos de $f: $(stat -c %a "$f") (escribible por otros)"; done
  for f in /etc/shadow /etc/gshadow; do
    [[ -e $f ]] && { (( 8#$(stat -c %a "$f") & 8#007 )) && mal "$f legible por todos" || ok "$f protegido"; }
  done

  # Escribibles por cualquiera en rutas de ejecución o arranque
  # Solo cuenta si un usuario sin privilegios puede llegar y escribir (respeta permisos de directorios)
  WW=""; WW_INACC=0
  while IFS= read -r f; do
    if runuser -u nobody -- test -w "$f" 2>/dev/null; then WW+="$f"$'\n'
    else WW_INACC=$((WW_INACC+1)); fi
  done < <(find /etc /usr /bin /sbin /lib /lib64 /opt /root /var/spool/cron -xdev -type f -perm -0002 2>/dev/null)
  if [[ -n "$WW" ]]; then
    mal "Ficheros del sistema escribibles por cualquier usuario:"; printf '%s' "$WW" | head -20 | sed 's/^/        /'
  else ok "Ningún fichero del sistema escribible por usuarios sin privilegios"; fi
  (( WW_INACC > 0 )) && info "$WW_INACC ficheros con permiso o+w pero inaccesibles (dentro de directorios cerrados, p. ej. /root)"

  # Scripts de cron / systemd que pueden modificar otros usuarios
  while read -r f; do mal "Tarea programada/servicio modificable por otros: $f"; done < <(
    find /etc/cron* /etc/systemd/system /usr/lib/systemd/system -xdev \( -perm -0002 -o -perm -0020 \) -type f 2>/dev/null)

  # Directorios con permisos de escritura en el PATH de root
  IFS=: read -ra P <<< "$PATH"
  declare -A VISTO=()
  for d in "${P[@]}"; do
    [[ -d $d ]] || continue
    r=$(readlink -f "$d"); [[ -n ${VISTO[$r]:-} ]] && continue; VISTO[$r]=1
    if (( 8#$(stat -Lc %a "$r") & 8#022 )); then mal "Directorio del PATH de root escribible por otros: $d"; fi
  done
else
  av "Sin root: se omiten SUID, capabilities y permisos"
fi

# /tmp y /dev/shm con noexec
for mp in /tmp /dev/shm /var/tmp; do
  o=$(findmnt -no OPTIONS "$mp" 2>/dev/null)
  if [[ -z "$o" ]]; then info "$mp no es un punto de montaje separado"
  elif [[ $o == *noexec* && $o == *nosuid* ]]; then ok "$mp montado con noexec,nosuid"
  else av "$mp sin noexec/nosuid (los exploits suelen ejecutarse desde aquí)"; fi
done

# =============================================================================
tit "10. Registro y detección"
# =============================================================================
systemctl is-active auditd >/dev/null 2>&1 && ok "auditd activo" || av "auditd no activo (sin registro de auditoría)"
if tiene aide || tiene tripwire; then ok "Control de integridad (AIDE/Tripwire) instalado"
else av "Sin control de integridad de ficheros (AIDE)"; fi
if tiene rkhunter; then info "rkhunter instalado: ejecútalo con 'rkhunter --check --sk'"; fi
systemctl is-active wazuh-agent >/dev/null 2>&1 && ok "Agente Wazuh activo"

# Intentos de acceso recientes
if tiene journalctl; then
  FALLOS=$(journalctl -q --since "-24h" -u ssh -u sshd 2>/dev/null | grep -ciE 'failed password|invalid user' || true)
  (( FALLOS > 100 )) && av "$FALLOS intentos de acceso SSH fallidos en 24 h" || info "$FALLOS intentos SSH fallidos en 24 h"
fi

# =============================================================================
tit "11. Vías de root publicadas en 2026 (0-day y explotadas activamente)"
# =============================================================================
info "Lista fija revisada el ${DATOS_0DAY}. Un 0-day sin publicar no se detecta: aquí se mira lo ya conocido y la superficie que suelen usar"
DIAS_LISTA=$(( ( $(date +%s) - $(date -d "$DATOS_0DAY" +%s) ) / 86400 ))
(( DIAS_LISTA > 45 )) && av "La lista tiene ${DIAS_LISTA} días: actualiza el script y usa --kev"

# --- a) Módulos que usan los exploits públicos. Se cargan solos al pedirlos un usuario
#        normal, así que 'no está cargado' no protege: solo cuenta que esté BLOQUEADO.
mod_estado() { # → noexiste | integrado | bloqueado | bloqueado_cargado | cargado | cargable
  local m=$1 f r cargado=0
  grep -q "^${m//-/_} " /proc/modules 2>/dev/null && cargado=1
  f=$(modinfo -F filename "$m" 2>/dev/null) || { (( cargado )) && echo cargado || echo noexiste; return; }
  [[ $f == *builtin* ]] && { echo integrado; return; }
  r=$(modprobe -n -v "$m" 2>/dev/null | tail -1)
  if [[ $r == install*/bin/false* || $r == install*/bin/true* ]]; then
    (( cargado )) && echo bloqueado_cargado || echo bloqueado
  elif (( cargado )); then echo cargado
  else echo cargable; fi
}
VIAS=(
  "algif_aead|Copy Fail (CVE-2026-31431) y CVE-2025-39964|cifrado AF_ALG desde programas de usuario"
  "esp4|Dirty Frag y Fragnesia (CVE-2026-43284, CVE-2026-46300)|IPsec"
  "esp6|Dirty Frag y Fragnesia (CVE-2026-43284, CVE-2026-46300)|IPsec"
  "rxrpc|Dirty Frag (CVE-2026-43500)|AFS"
  "openvswitch|OVSwrap (CVE-2026-64531)|Open vSwitch"
)
BLOQUEAR=()
if [[ $(sysctl -n kernel.modules_disabled 2>/dev/null) == 1 ]]; then
  ok "kernel.modules_disabled = 1: no se puede cargar ningún módulo nuevo"
elif ! tiene modprobe || ! tiene modinfo; then
  info "Sin modprobe/modinfo (¿contenedor?): no puedo comprobar los módulos"
else
  for v in "${VIAS[@]}"; do
    IFS='|' read -r m nombre uso <<<"$v"
    case "$(mod_estado "$m")" in
      noexiste)          ok  "$m no existe en este kernel — $nombre" ;;
      bloqueado)         ok  "$m bloqueado — $nombre" ;;
      integrado)         info "$m va integrado en el kernel: solo protege el parche — $nombre" ;;
      bloqueado_cargado) av  "$m bloqueado pero sigue cargado (rmmod $m o reinicia) — $nombre" ;;
      cargado)           av  "$m cargado y sin bloquear — $nombre. Si no usas $uso, bloquéalo"; BLOQUEAR+=("$m") ;;
      cargable)          av  "$m lo puede cargar cualquier usuario — $nombre. Si no usas $uso, bloquéalo"; BLOQUEAR+=("$m") ;;
    esac
  done
  if (( ${#BLOQUEAR[@]} )); then
    info "Para bloquearlos (rompe IPsec/AFS/Open vSwitch si los usas; WireGuard no se ve afectado):"
    echo "        printf 'install %s /bin/false\\n' ${BLOQUEAR[*]} | sudo tee /etc/modprobe.d/bloqueo-0day.conf"
  fi
fi
(( USERNS_LIBRE )) && info "User namespaces libres (sección 4): los exigen OVSwrap y CVE-2026-53366, y facilitan Fragnesia"

# --- b) Kernel en uso frente a las versiones corregidas
#   CVE | nombre | primera versión afectada | primeras versiones corregidas por serie
KCVES=(
  "CVE-2026-46300|Fragnesia (incluye los parches anteriores de Copy Fail y Dirty Frag)||5.10.257 5.15.208 6.1.174 6.6.141 6.12.91 6.18.33 7.0.10 7.1"
  "CVE-2026-53362|IPv6 fraggap, en KEV (y CVE-2026-53366 en IPv4)|6.0|6.1.177 6.6.144 6.12.95 6.18.38 7.1.3"
  "CVE-2026-64531|OVSwrap||5.15.212 6.1.178 6.6.145 6.12.97 6.18.40 7.1.5"
  "CVE-2026-98432|TCP IPv4, REMOTO sin autenticar||5.10.272 5.15.223 6.1.190 6.6.159 6.12.113 6.18.56 7.2.10 7.3"
)
KV=$(uname -r | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?')
if [[ $ID == fedora && -n $KV ]]; then
  # Comparación orientativa con las series incluidas en la tabla de versiones upstream.
  for k in "${KCVES[@]}"; do
    IFS='|' read -r c nombre min lista <<<"$k"
    e=$(serie_estado "$KV" "$min" "$lista")
    case $e in
      ok)     ok  "Kernel $KV corregido para $c — $nombre" ;;
      na)     ok  "Kernel $KV no afectado por $c — $nombre" ;;
      vuln:*) mal "Kernel $KV VULNERABLE a $c — $nombre (corregido en ${e#vuln:}). Actualiza y reinicia" ;;
      unknown) av "Kernel $KV: serie no cubierta por la tabla para $c; consulta los avisos de Fedora" ;;
    esac
  done
elif (( SIN_RED )); then
  info "Kernel con parches retroportados: la versión no basta y con --sin-red no consulto los avisos"
elif [[ $FAM == deb ]] && ! tiene pro; then
  info "Kernel con parches retroportados: sin el cliente 'pro' no puedo comprobar estos CVE: ${KCVES[*]%%|*}"
else
  # Ubuntu/RHEL retroportan: se pregunta al gestor de paquetes (mira lo INSTALADO; el reinicio va en la sección 2)
  for k in "${KCVES[@]}"; do
    IFS='|' read -r c nombre min lista <<<"$k"
    cve_pend "$c"; case $? in
      0) mal "$c — $nombre: sin resolver o con parche SIN aplicar" ;;
      1) ok  "$c — $nombre: sin parche pendiente" ;;
      *) av  "$c — $nombre: no pude consultarlo" ;;
    esac
  done
fi

# --- c) Programas de usuario con fallo de root reciente
if [[ $FAM == deb ]]; then
  NR=""; APTF=""
  case "$ID:${VERSION_ID:-}" in
    ubuntu:26.10) NR=3.11-1ubuntu2.26.10.1; APTF=3.3.3ubuntu0.1 ;;
    ubuntu:26.04) NR=3.11-1ubuntu2.26.04.1; APTF=3.2.1ubuntu0.1 ;;
    ubuntu:24.04) NR=3.6-7ubuntu4.6;        APTF=2.8.4ubuntu0.1 ;;
    ubuntu:22.04) NR=3.5-5ubuntu2.6;        APTF=2.4.15ubuntu0.1 ;;
    debian:13)    NR=3.11-1.1~deb13u2 ;;
    debian:12)    NR=3.6-4+deb12u4 ;;
    debian:11)    APTF=2.2.5 ;;
  esac
  deb_min() { # paquete  versión_corregida  descripción
    local inst; inst=$(dpkg-query -W -f='${db:Status-Status} ${Version}' "$1" 2>/dev/null) || return 0
    [[ $inst == installed\ * ]] || return 0; inst=${inst#installed }
    if [[ -z $2 ]]; then info "$1 $inst — $3: no tengo la versión corregida para ${PRETTY_NAME}, compruébala"
    elif dpkg --compare-versions "$inst" ge "$2"; then ok "$1 $inst corregido — $3"
    else mal "$1 $inst VULNERABLE — $3 (corregido en $2)"; fi
  }
  deb_min needrestart "$NR"   "CVE-2026-124757: un usuario local pasa a root cuando root ejecuta apt"
  deb_min apt         "$APTF" "CVE-2026-109518: quien controle la descarga HTTP cambia un paquete y ejecuta código como root"
  HTTP=$(grep -rhsE '^[[:space:]]*(deb|URIs:)[[:space:]].*http://' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -c . || true)
  (( HTTP > 0 )) && info "$HTTP orígenes de APT por HTTP sin cifrar (es por donde se explota CVE-2026-109518)"
elif rpm -q needrestart >/dev/null 2>&1; then
  NRV=$(rpm -q --qf '%{VERSION}' needrestart)
  vge "$NRV" 3.11.1 && ok "needrestart $NRV corregido — CVE-2026-124757" \
    || av "needrestart $NRV — CVE-2026-124757 se corrige en 3.11.1: comprueba si tu distribución lo retroportó"
fi

# PHP2Shell: ejecución remota en PHP que se encadena con Fragnesia para llegar a root
PHPV=$( { php -r 'echo PHP_VERSION;' 2>/dev/null || php-fpm -v 2>/dev/null | awk 'NR==1{print $2}'; } | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' )
if [[ -n $PHPV ]]; then
  e=$(serie_estado "$PHPV" "" "8.2.35 8.3.36 8.4.27 8.5.12")
  if [[ $ID != fedora ]]; then
    info "PHP $PHPV — PHP2Shell (CVE-2026-109618/109619) se corrige en 8.2.35, 8.3.36, 8.4.27 y 8.5.12; tu distribución retroporta: fíate de la sección 3"
  else case $e in
    ok)     ok  "PHP $PHPV corregido para PHP2Shell (CVE-2026-109618/109619)" ;;
    vuln:*) mal "PHP $PHPV VULNERABLE a PHP2Shell (CVE-2026-109618/109619), corregido en ${e#vuln:}" ;;
    *)      av  "PHP $PHPV: serie no cubierta por la tabla de PHP2Shell (CVE-2026-109618/109619)" ;;
  esac; fi
fi

# --- d) Rastro de explotación: Copy Fail, Dirty Frag y Fragnesia alteran un binario SUID
#        solo en memoria (caché de páginas). Comparar con el paquete lo delata.
if [[ $EUID -eq 0 ]]; then
  ALT=""; REV=0
  for b in su sudo passwd mount umount pkexec newgrp chsh chfn gpasswd; do
    f=$(command -v "$b" 2>/dev/null) || continue; f=$(readlink -f "$f")
    if [[ $FAM == rpm ]]; then
      rpm -qf "$f" >/dev/null 2>&1 || continue; REV=$((REV+1))
      rpm -Vf "$f" --noscripts 2>/dev/null | awk -v f="$f" '$NF==f && $1 ~ /^..5/' | grep -q . && ALT+="$f "
    else
      p=$(dpkg -S "$f" 2>/dev/null | head -1 | cut -d: -f1)
      [[ -z $p ]] && p=$(dpkg -S "${f#/usr}" 2>/dev/null | head -1 | cut -d: -f1)
      [[ -z $p ]] && continue; REV=$((REV+1))
      dpkg --verify "$p" 2>/dev/null | awk -v a="$f" -v b="${f#/usr}" '($NF==a || $NF==b) && $1 ~ /^..5/' | grep -q . && ALT+="$f "
    fi
  done
  if [[ -n $ALT ]]; then mal "Binarios SUID que NO coinciden con su paquete (posible explotación, investiga ya): $ALT"
  elif (( REV > 0 )); then ok "$REV binarios SUID clave coinciden con su paquete"
  else info "No pude comparar los binarios SUID con sus paquetes"; fi
fi

# =============================================================================
if (( USAR_KEV )); then
tit "12. CVE explotados activamente (catálogo KEV de CISA)"
# =============================================================================
  URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  if (( SIN_RED )); then info "Omitido por --sin-red"
  elif ! tiene jq; then av "Falta jq para esta comprobación"
  elif ! KEV=$(curl -fsSL --max-time 40 "$URL"); then av "No se pudo descargar el catálogo KEV"
  else
    # OpenSSH, glibc y polkit figuran con otro fabricante (OpenBSD, GNU, Red Hat): se mira también el producto
    CVES=$(jq -r '.vulnerabilities[]
                  | select((.vendorProject+" | "+.product)|test("^Linux \\||sudo|OpenSSH|polkit|C Library|glibc";"i"))
                  | select(.dateAdded >= "2024-01-01") | .cveID' <<<"$KEV" | sort -u)
    info "$(printf '%s\n' "$CVES" | grep -c .) CVE de Linux/sudo/OpenSSH/polkit/glibc en KEV desde 2024"
    PEND=0; SIN_DATO=0
    if [[ $FAM == deb ]] && ! tiene pro; then av "En Ubuntu necesito el cliente 'pro' (ubuntu-advantage-tools) para cruzar CVE"
    else
      for c in $CVES; do
        cve_pend "$c"; case $? in
          0) mal "$c: sin resolver o con parche SIN aplicar"; PEND=$((PEND+1)) ;;
          2) SIN_DATO=$((SIN_DATO+1)) ;;
        esac
      done
      (( SIN_DATO > 0 )) && av "$SIN_DATO CVE del KEV sin poder consultar (¿sin red o gestor de paquetes sin esa opción?)"
      (( PEND == 0 && SIN_DATO == 0 )) && ok "Ningún CVE del KEV con parche pendiente"
      [[ ${ID} == fedora ]] && info "Fedora no etiqueta todos los CVE del kernel en sus avisos: cuenta también la versión del kernel (sección 11)"
    fi
  fi
fi

# =============================================================================
if (( USAR_LYNIS )); then
tit "13. Lynis"
  if (( SIN_RED )); then info "Lynis omitido por --sin-red"
  elif tiene lynis; then lynis audit system --quick --no-colors 2>/dev/null | sed -n '/Lynis security scan details/,$p'
  else av "Lynis no instalado (apt/dnf install lynis)"; fi
fi

# =============================================================================
tit "RESUMEN"
echo "  ${V}OK: $N_OK${F}   ${A}Avisos: $N_AV${F}   ${R}Fallos: $N_MAL${F}"
if (( N_MAL > 0 )); then
  echo "  ${R}Hay fallos graves. Empieza por: parches pendientes → reiniciar → SSH → SUID.${F}"; exit 2
elif (( N_AV > 0 )); then
  echo "  ${A}Sin fallos graves, pero hay avisos que conviene revisar.${F}"; exit 1
else
  echo "  ${V}Todo correcto en lo que este script puede comprobar.${F}"; exit 0
fi
