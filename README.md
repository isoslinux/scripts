# IsosLinux Scripts

Community Linux utilities / Utilidades Linux para la comunidad.

- [English](#english)
- [Castellano](#castellano)
- [Source / Código fuente](auditoria-seguridad.sh)

## English

### Linux security audit

`auditoria-seguridad.sh` runs a **local configuration audit** on Linux machines you administer. It targets Ubuntu and Debian, plus Fedora, RHEL, CentOS, Rocky Linux and AlmaLinux. Some checks depend on the distribution, its package metadata, optional utilities and the privileges available. A VM sees its own kernel and settings. Results from containers or hosts with provider-managed kernels can be incomplete.

### Download and run

Download [auditoria-seguridad.sh](https://raw.githubusercontent.com/isoslinux/scripts/main/auditoria-seguridad.sh). Read the file before running it. Start with a representative VM. For production, review the checks, use a low-load window and keep the report private. The script can read package metadata, logs and file trees. It does not install updates or restart services. In normal operation it can refresh the package-manager cache.

~~~bash
bash -n auditoria-seguridad.sh
sudo bash auditoria-seguridad.sh --sin-red
sudo bash auditoria-seguridad.sh --informe ./audit-report.txt
~~~

| Option | Effect |
| --- | --- |
| `--sin-red` | Skips explicit online lookups, uses local APT metadata and forces DNF cache-only mode. KEV and Lynis are skipped. Use network isolation if you need a strict no-egress guarantee. |
| `--kev` | Fetches the CISA Known Exploited Vulnerabilities catalog and checks a subset against available distribution data. Uses `curl` and `jq`. Ubuntu package lookups require the `pro` client. |
| `--lynis` | Runs the optional Lynis quick audit when already installed. Lynis manages its own output and may write its own reports. |
| `--informe FILE` | Writes a new plain-text report and refuses to overwrite an existing file. Use a private directory. |
| `--help` | Shows usage. |

### What each section checks

| Section | Checks |
| --- | --- |
| 1. OS support | Detects the distribution. Checks Ubuntu support status when tooling is present and prints guidance for Fedora. |
| 2. Kernel and reboot | Compares the running kernel with installed kernels, checks reboot indicators and reports live patching when detected. Checks the version of `needrestart` later without executing it. |
| 3. Updates | Looks for security updates and automatic-update settings. Package query failures are reported as unverified. Cache-only results depend on metadata freshness. |
| 4. Kernel hardening | Reviews selected sysctl settings, user namespaces, loaded modules, Secure Boot and kernel lockdown. |
| 5. Mandatory access control | Reports SELinux or AppArmor status where detectable. |
| 6. Accounts and sudo | Checks extra UID 0 accounts, empty passwords where readable, administrative groups, sudo rules and related file permissions. |
| 7. SSH | Inspects effective SSH server settings when available and looks for Fail2ban or CrowdSec. |
| 8. Network | Looks for common local firewalls and listening services. Confirm reachability separately with the firewall and network configuration. |
| 9. Permissions | Reviews SUID/SGID files, capabilities, system paths, scheduled tasks and temporary mount options. Some checks require root. |
| 10. Logging | Looks for audit, integrity and monitoring tools and summarizes recent SSH login failures. |
| 11. Selected published CVEs | Checks a dated list against selected kernel series and packages, inspects relevant modules and compares selected binaries with package metadata. Missing coverage and backported fixes require vendor advisories. |
| 12. CISA KEV | Optional comparison against selected published entries from the CISA catalog. |
| 13. Lynis | Optional quick audit with the installed Lynis executable. |

### Interpreting results

Exit status `0` means the checks that ran reported no findings. `1` means warnings, `2` means serious findings under the script’s rules and `3` indicates a usage, unsupported-distribution or report setup error. Treat findings as leads and verify them before changing access, kernel modules or services. The fixed CVE list was last reviewed in the input on 24 November 2026. Check official vendor advisories for current status and backports. A clean result gives no assurance about issues outside the checks performed. Share only redacted excerpts, since reports may contain hostnames, usernames, ports, local paths and configuration details.

## Castellano

### Auditoría de seguridad Linux

`auditoria-seguridad.sh` realiza una **auditoría local de configuración** en equipos Linux que administras. Está orientado a Ubuntu y Debian, además de Fedora, RHEL, CentOS, Rocky Linux y AlmaLinux. Algunas comprobaciones dependen de la distribución, sus metadatos, las herramientas instaladas y los permisos. Una VM ve su propio kernel y configuración. Los resultados pueden ser parciales en contenedores o si el proveedor gestiona el kernel.

### Descarga y ejecución

Descarga [auditoria-seguridad.sh](https://raw.githubusercontent.com/isoslinux/scripts/main/auditoria-seguridad.sh). Lee el archivo antes de ejecutarlo. Empieza en una VM representativa. En producción, revisa las comprobaciones, elige un momento de baja carga y guarda el informe en privado. El script consulta información de paquetes, registros y archivos. No instala actualizaciones ni reinicia servicios. En el modo normal puede actualizar la caché del gestor de paquetes.

~~~bash
bash -n auditoria-seguridad.sh
sudo bash auditoria-seguridad.sh --sin-red
sudo bash auditoria-seguridad.sh --informe ./informe-auditoria.txt
~~~

| Opción | Efecto |
| --- | --- |
| `--sin-red` | Omite las consultas explícitas en línea, usa índices locales de APT y fuerza el modo de solo caché de DNF. Omite KEV y Lynis. Usa aislamiento de red si necesitas garantizar que no haya tráfico saliente. |
| `--kev` | Descarga el catálogo de vulnerabilidades explotadas conocidas de CISA y cruza un subconjunto con los datos disponibles. Usa `curl` y `jq`. En Ubuntu, la consulta de paquetes requiere el cliente `pro`. |
| `--lynis` | Ejecuta la auditoría rápida opcional de Lynis si ya está instalado. Lynis gestiona su propia salida y puede escribir sus propios informes. |
| `--informe ARCHIVO` | Escribe un informe nuevo en texto plano y rechaza sobrescribir un archivo existente. Usa un directorio privado. |
| `--help` | Muestra las opciones de uso. |

### Qué comprueba cada sección

| Sección | Comprobaciones |
| --- | --- |
| 1. Sistema y soporte | Detecta la distribución. Comprueba el soporte de Ubuntu si dispone de la herramienta y muestra orientación para Fedora. |
| 2. Kernel y reinicio | Compara el kernel activo con los instalados, revisa si hay reinicios pendientes e indica si detecta parches en vivo. Más adelante consulta la versión de `needrestart` sin ejecutarlo. |
| 3. Actualizaciones | Busca actualizaciones de seguridad y comprueba si están automatizadas. Si falla la consulta, lo indica. En modo caché importa la antigüedad de los metadatos. |
| 4. Endurecimiento del kernel | Revisa parámetros sysctl, espacios de nombres de usuario, módulos cargados, Secure Boot y lockdown. |
| 5. Control de acceso obligatorio | Informa del estado de SELinux o AppArmor cuando puede detectarlo. |
| 6. Cuentas y sudo | Revisa cuentas adicionales con UID 0, contraseñas vacías cuando puede comprobarlas, grupos administrativos, reglas de sudo y permisos de sus archivos. |
| 7. SSH | Consulta la configuración efectiva del servidor SSH y la presencia de Fail2ban o CrowdSec. |
| 8. Red | Busca cortafuegos locales habituales y servicios escuchando. Comprueba el alcance real por separado con las reglas de red y cortafuegos. |
| 9. Permisos | Revisa archivos SUID/SGID, capacidades, rutas del sistema, tareas programadas y opciones de montajes temporales. Algunas comprobaciones requieren root. |
| 10. Registros | Busca herramientas de auditoría, integridad y monitorización y resume los accesos SSH fallidos recientes. |
| 11. CVE publicados seleccionados | Contrasta una lista fechada con ciertas series del kernel y paquetes, inspecciona módulos y compara algunos binarios con los metadatos de sus paquetes. Consulta los avisos del proveedor para casos fuera de cobertura o parches retroportados. |
| 12. KEV de CISA | Cruce opcional con determinadas entradas publicadas en el catálogo de CISA. |
| 13. Lynis | Auditoría rápida opcional con el ejecutable de Lynis instalado. |

### Cómo interpretar los resultados

El código `0` indica que los controles ejecutados no señalaron hallazgos. `1` indica avisos, `2` hallazgos graves según las reglas del script y `3` un error de uso, distribución no admitida o fallo al abrir el informe. Verifica los hallazgos antes de cambiar SSH, módulos del kernel o servicios. La fecha de revisión de la lista fija en el archivo original es el 24 de noviembre de 2026. Consulta los avisos oficiales para confirmar el estado actual y los parches retroportados. Comparte solo extractos anonimizados. El informe puede contener nombres de equipo, usuarios, puertos, rutas y detalles de configuración.
