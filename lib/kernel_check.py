"""
Módulo central de verificación de vulnerabilidad CVE-2026-31431 (Copy Fail).

Contiene la lógica de comparación de versiones de kernel, detección de distribución,
y evaluación de vulnerabilidad compartida por todos los scripts.

Fuentes:
  - https://cert.europa.eu/publications/security-advisories/2026-005/
  - https://www.sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds
  - https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation
  - https://discourse.ubuntu.com/t/fixes-available-for-cve-2026-31431-copy-fail/81498
  - https://www.suse.com/c/suse-responds-to-the-copy-fail-vulnerability/
  - https://kb.ciq.com/article/rocky-linux/rl-cve-2026-31431-mitigation
  - https://explore.alas.aws.amazon.com/CVE-2026-31431.html
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Versiones parcheadas conocidas por distribución (al 4 mayo 2026)
# ---------------------------------------------------------------------------
# Mainline fixes
MAINLINE_FIXED = ["7.0.0", "6.19.12", "6.18.22"]

# Versión mínima vulnerable (introducida en kernel 4.14, julio 2017)
VULN_INTRODUCED = "4.14.0"

# Distribuciones con parches confirmados y sus versiones fijas
# Formato: regex de distro -> lista de (regex kernel vulnerable, kernel fixed)
DISTRO_PATCHES = {
    # Ubuntu: kmod mitigation disponible, kernel fix pendiente para la mayoría
    # Ubuntu 26.04 (Resolute) NO está afectado
    "ubuntu_2604": {"status": "not_affected", "note": "Ubuntu 26.04 (Resolute) no está afectado"},
    "ubuntu": {
        "status": "mitigation_available",
        "note": "Mitigación via kmod disponible. Kernel fix pendiente.",
        "kmod_fixed": {
            "14.04": "15-0ubuntu7+esm1",
            "16.04": "22-1ubuntu5.2+esm1",
            "18.04": "24-1ubuntu3.5+esm1",
            "20.04": "27-1ubuntu2.1+esm1",
            "22.04": "29-1ubuntu1.1",
            "24.04": "31+20240202-2ubuntu7.2",
            "25.10": "34.2-2ubuntu1.1",
        },
    },
    # Amazon Linux - Pendiente según ALAS
    "amzn2023": {"status": "pending", "note": "Parche pendiente según ALAS (al 4 mayo 2026)"},
    "amzn2": {"status": "pending", "note": "Parche pendiente según ALAS (al 4 mayo 2026)"},
    # SUSE - Parches publicados el 3 mayo 2026
    "suse": {
        "status": "fixed",
        "note": "SUSE publicó parches el 3 mayo 2026 para todas las versiones mantenidas.",
        "fixed_versions": {
            "tumbleweed": "6.19.12",
            "slowroll": "6.18.22",
        },
    },
    # RHEL - Fix en progreso
    "rhel": {"status": "pending", "note": "Red Hat clasificó como Important. Fix en progreso."},
    # Rocky Linux - Parches CIQ disponibles para LTS
    "rocky": {
        "status": "partial",
        "note": "Parches CIQ disponibles para variantes LTS. Kernels estándar pendientes.",
        "fixed_versions": {
            "9.2": "5.14.0-284.30.1",
            "9.4": "5.14.0-427.42.1",
            "9.6": "5.14.0-570.60.1",
            "8.6": "4.18.0-372.32.1",
        },
    },
    # AlmaLinux - Parches en producción desde 1 mayo 2026
    "alma": {"status": "fixed", "note": "Parches en repos de producción desde 1 mayo 2026."},
    # Debian - Afectado, status similar a Ubuntu
    "debian": {"status": "pending", "note": "Afectado. Verificar tracker de seguridad Debian."},
    # Oracle Linux
    "oracle": {"status": "pending", "note": "Afectado. Verificar Oracle Linux Security Advisories."},
    # Fedora
    "fedora": {"status": "pending", "note": "Afectado. Verificar Fedora Updates."},
    # CentOS
    "centos": {"status": "pending", "note": "Afectado. Sin soporte oficial para CentOS 8+."},
}

# Nota sobre CONFIG_CRYPTO_USER_API_AEAD
# En RHEL/Rocky/CentOS/Oracle (EL kernels): compilado como =y (built-in)
# En Ubuntu/Debian/SUSE: compilado como =m (módulo cargable)
EL_DISTROS = ["rhel", "rocky", "centos", "oracle", "alma", "fedora"]


@dataclass
class VulnerabilityResult:
    """Resultado de la evaluación de vulnerabilidad para un host."""

    hostname: str
    kernel_version: str = ""
    distro: str = ""
    distro_version: str = ""
    arch: str = ""
    algif_status: str = ""  # "loaded", "available", "built-in", "not_available", "unknown"
    mitigation_modprobe: bool = False
    mitigation_boot_param: bool = False
    kmod_version: str = ""
    status: str = "UNKNOWN"  # VULNERABLE, MITIGADO, NO_VULNERABLE, PROBABLEMENTE_VULNERABLE, UNKNOWN
    details: str = ""
    recommendations: list = field(default_factory=list)

    @property
    def is_mitigated(self) -> bool:
        return self.mitigation_modprobe or self.mitigation_boot_param

    @property
    def status_emoji(self) -> str:
        return {
            "VULNERABLE": "🔴",
            "PROBABLEMENTE_VULNERABLE": "🟠",
            "MITIGADO": "🟡",
            "NO_VULNERABLE": "🟢",
            "UNKNOWN": "⚪",
        }.get(self.status, "⚪")


# ---------------------------------------------------------------------------
# Utilidades de versión
# ---------------------------------------------------------------------------
def parse_kernel_version(version_str: str) -> tuple:
    """Extrae major.minor.patch de una cadena de versión de kernel."""
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version_str.strip())
    if match:
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    match = re.match(r"(\d+)\.(\d+)", version_str.strip())
    if match:
        return (int(match.group(1)), int(match.group(2)), 0)
    return (0, 0, 0)


def version_gte(v1: str, v2: str) -> bool:
    """True si v1 >= v2."""
    return parse_kernel_version(v1) >= parse_kernel_version(v2)


def version_lt(v1: str, v2: str) -> bool:
    """True si v1 < v2."""
    return parse_kernel_version(v1) < parse_kernel_version(v2)


def is_kernel_vulnerable(kernel_version: str) -> bool:
    """
    Determina si un kernel está en el rango vulnerable.
    Vulnerable: >= 4.14.0 y no en versiones parcheadas mainline.
    """
    kv = parse_kernel_version(kernel_version)

    # Anterior a la introducción del bug
    if kv < parse_kernel_version(VULN_INTRODUCED):
        return False

    # >= 7.0.0 está parcheado
    if kv >= (7, 0, 0):
        return False

    # Verificar ramas parcheadas específicas
    for fixed in MAINLINE_FIXED:
        fv = parse_kernel_version(fixed)
        # Misma rama major.minor
        if kv[0] == fv[0] and kv[1] == fv[1]:
            if kv >= fv:
                return False

    return True


def detect_distro(os_release_content: str) -> tuple:
    """
    Detecta distribución y versión desde el contenido de /etc/os-release.
    Retorna (distro_key, distro_name, version).
    """
    distro_id = ""
    distro_name = ""
    version = ""

    for line in os_release_content.splitlines():
        line = line.strip()
        if line.startswith("ID="):
            distro_id = line.split("=", 1)[1].strip('"').lower()
        elif line.startswith("PRETTY_NAME="):
            distro_name = line.split("=", 1)[1].strip('"')
        elif line.startswith("VERSION_ID="):
            version = line.split("=", 1)[1].strip('"')

    # Mapear a nuestras claves
    key_map = {
        "ubuntu": "ubuntu",
        "amzn": "amzn2023",  # se refina abajo
        "rhel": "rhel",
        "centos": "centos",
        "rocky": "rocky",
        "almalinux": "alma",
        "ol": "oracle",
        "oracle": "oracle",
        "fedora": "fedora",
        "debian": "debian",
        "sles": "suse",
        "opensuse-leap": "suse",
        "opensuse-tumbleweed": "suse",
    }

    distro_key = key_map.get(distro_id, distro_id)

    # Refinar Amazon Linux
    if distro_id == "amzn":
        if version.startswith("2023") or version == "2023":
            distro_key = "amzn2023"
        else:
            distro_key = "amzn2"

    # Ubuntu 26.04
    if distro_key == "ubuntu" and version.startswith("26.04"):
        distro_key = "ubuntu_2604"

    return distro_key, distro_name, version


def is_el_distro(distro_key: str) -> bool:
    """Determina si es una distribución Enterprise Linux (kernel built-in)."""
    return distro_key in EL_DISTROS


def evaluate_vulnerability(result: VulnerabilityResult) -> VulnerabilityResult:
    """
    Evalúa el estado de vulnerabilidad completo basándose en los datos recopilados.
    Modifica y retorna el objeto VulnerabilityResult.
    """
    recommendations = []

    # Sin kernel version -> no podemos evaluar
    if not result.kernel_version:
        result.status = "UNKNOWN"
        result.details = "No se pudo determinar la versión del kernel"
        result.recommendations = ["Verificar manualmente con: uname -r"]
        return result

    # Kernel no vulnerable (anterior a 4.14 o ya parcheado mainline)
    if not is_kernel_vulnerable(result.kernel_version):
        result.status = "NO_VULNERABLE"
        result.details = f"Kernel {result.kernel_version} no está en el rango vulnerable"
        return result

    # Kernel en rango vulnerable - verificar mitigaciones
    if result.is_mitigated:
        result.status = "MITIGADO"
        mitigations = []
        if result.mitigation_modprobe:
            mitigations.append("modprobe blacklist")
        if result.mitigation_boot_param:
            mitigations.append("initcall_blacklist boot param")
        result.details = (
            f"Kernel {result.kernel_version} vulnerable pero mitigación activa: "
            + ", ".join(mitigations)
        )
        recommendations.append("Actualizar kernel cuando el parche esté disponible")
        recommendations.append("Verificar que la mitigación no afecte workloads (IPsec ESN, cryptsetup)")
    else:
        result.status = "VULNERABLE"
        result.details = f"Kernel {result.kernel_version} vulnerable. Sin mitigación aplicada."

        # Recomendaciones según tipo de distro
        if is_el_distro(result.distro):
            recommendations.append(
                "MITIGACIÓN (EL kernel, built-in): "
                'sudo grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init" && sudo reboot'
            )
        else:
            recommendations.append(
                "MITIGACIÓN INMEDIATA: "
                'echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif.conf && '
                "sudo rmmod algif_aead 2>/dev/null || true"
            )

        recommendations.append("Actualizar kernel cuando el vendor publique el parche")
        recommendations.append("En contenedores: bloquear AF_ALG via seccomp")

    # Agregar info de distro
    distro_info = DISTRO_PATCHES.get(result.distro, {})
    if isinstance(distro_info, dict) and "note" in distro_info:
        result.details += f" | Vendor: {distro_info['note']}"

    result.recommendations = recommendations
    return result


# ---------------------------------------------------------------------------
# Comandos de verificación remota (shell)
# ---------------------------------------------------------------------------
CHECK_COMMANDS = """
echo '===KERNEL==='
uname -r
echo '===ARCH==='
uname -m
echo '===OS_RELEASE==='
cat /etc/os-release 2>/dev/null || echo 'unknown'
echo '===MODULE_LOADED==='
grep -c '^algif_aead ' /proc/modules 2>/dev/null || echo '0'
echo '===MODULE_AVAILABLE==='
modinfo algif_aead >/dev/null 2>&1 && echo 'module' || echo 'not_module'
echo '===BUILTIN==='
grep -c 'CONFIG_CRYPTO_USER_API_AEAD=y' /boot/config-$(uname -r) 2>/dev/null || echo '-1'
echo '===MITIGATION_MODPROBE==='
grep -rl 'algif_aead' /etc/modprobe.d/ 2>/dev/null | xargs grep -l '/bin/false' 2>/dev/null | wc -l
echo '===MITIGATION_BOOT==='
grep -c 'initcall_blacklist=algif_aead_init' /proc/cmdline 2>/dev/null || echo '0'
echo '===KMOD_VERSION==='
dpkg -l kmod 2>/dev/null | grep ^ii | awk '{print $3}' || rpm -q kmod 2>/dev/null || echo 'unknown'
echo '===END==='
""".strip()


def parse_check_output(output: str, hostname: str = "unknown") -> VulnerabilityResult:
    """Parsea la salida del script de verificación remota."""
    result = VulnerabilityResult(hostname=hostname)

    sections = {}
    current = None
    for line in output.splitlines():
        if line.startswith("===") and line.endswith("==="):
            current = line.strip("=")
            sections[current] = []
        elif current:
            sections[current].append(line)

    # Kernel
    if "KERNEL" in sections and sections["KERNEL"]:
        result.kernel_version = sections["KERNEL"][0].strip()

    # Arch
    if "ARCH" in sections and sections["ARCH"]:
        result.arch = sections["ARCH"][0].strip()

    # OS Release
    if "OS_RELEASE" in sections:
        os_release = "\n".join(sections["OS_RELEASE"])
        distro_key, distro_name, distro_version = detect_distro(os_release)
        result.distro = distro_key
        result.distro_version = distro_version
        if distro_name:
            # Usar pretty name si está disponible
            result.distro = distro_key  # key para lógica interna

    # Módulo
    if "MODULE_LOADED" in sections:
        try:
            loaded = int(sections["MODULE_LOADED"][0].strip())
            if loaded > 0:
                result.algif_status = "loaded"
        except ValueError:
            pass

    if "MODULE_AVAILABLE" in sections:
        val = sections["MODULE_AVAILABLE"][0].strip() if sections["MODULE_AVAILABLE"] else ""
        if val == "module" and result.algif_status != "loaded":
            result.algif_status = "available"

    if "BUILTIN" in sections:
        try:
            val = int(sections["BUILTIN"][0].strip())
            if val > 0:
                result.algif_status = "built-in"
        except ValueError:
            pass

    if not result.algif_status:
        result.algif_status = "unknown"

    # Mitigaciones
    if "MITIGATION_MODPROBE" in sections:
        try:
            result.mitigation_modprobe = int(sections["MITIGATION_MODPROBE"][0].strip()) > 0
        except ValueError:
            pass

    if "MITIGATION_BOOT" in sections:
        try:
            result.mitigation_boot_param = int(sections["MITIGATION_BOOT"][0].strip()) > 0
        except ValueError:
            pass

    # Kmod version
    if "KMOD_VERSION" in sections and sections["KMOD_VERSION"]:
        result.kmod_version = sections["KMOD_VERSION"][0].strip()

    # Evaluar
    return evaluate_vulnerability(result)


# ---------------------------------------------------------------------------
# Formato de salida
# ---------------------------------------------------------------------------
COLORS = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "CYAN": "\033[96m",
    "BOLD": "\033[1m",
    "RESET": "\033[0m",
}


def colorize(text: str, color: str, force: bool = False) -> str:
    """Aplica color ANSI."""
    import sys
    if not force and not sys.stdout.isatty():
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['RESET']}"


def print_banner():
    """Imprime banner del proyecto."""
    import sys
    print()
    print(colorize("=" * 80, "CYAN"))
    print(colorize("  CVE-2026-31431 'Copy Fail' - Verificador de Vulnerabilidad", "BOLD"))
    print(colorize("  Escalación de privilegios local en kernel Linux (algif_aead)", "CYAN"))
    print(colorize("  CVSS: 7.8 HIGH | Afecta kernels >= 4.14 (desde 2017)", "CYAN"))
    print(colorize("=" * 80, "CYAN"))
    print()


def format_result_line(r: VulnerabilityResult) -> str:
    """Formatea una línea de resultado para tabla."""
    status_map = {
        "VULNERABLE": ("🔴 VULNERABLE", "RED"),
        "PROBABLEMENTE_VULNERABLE": ("🟠 PROB. VULNERABLE", "YELLOW"),
        "MITIGADO": ("🟡 MITIGADO", "YELLOW"),
        "NO_VULNERABLE": ("🟢 NO VULNERABLE", "GREEN"),
        "UNKNOWN": ("⚪ DESCONOCIDO", "RESET"),
    }
    status_text, color = status_map.get(r.status, ("⚪ ???", "RESET"))
    return colorize(status_text, color)


def print_results_table(results: list, title: str = "Resultados"):
    """Imprime tabla formateada de resultados."""
    if not results:
        print("  No se encontraron hosts para verificar.")
        return

    # Ordenar por severidad
    priority = {
        "VULNERABLE": 0,
        "PROBABLEMENTE_VULNERABLE": 1,
        "MITIGADO": 2,
        "UNKNOWN": 3,
        "NO_VULNERABLE": 4,
    }
    results.sort(key=lambda r: priority.get(r.status, 5))

    print(f"\n  {colorize(title, 'BOLD')}")
    print(f"  {'─' * 110}")
    print(f"  {'Host':<28} {'Distro':<24} {'Kernel':<24} {'Módulo':<12} {'Estado'}")
    print(f"  {'─' * 110}")

    for r in results:
        host = r.hostname[:27]
        distro = (r.distro or "N/A")[:23]
        kernel = (r.kernel_version or "N/A")[:23]
        module = r.algif_status[:11]
        status = format_result_line(r)

        print(f"  {host:<28} {distro:<24} {kernel:<24} {module:<12} {status}")
        if r.details:
            print(f"  {'':>28} └─ {r.details[:80]}")

    print(f"  {'─' * 110}")


def print_summary(results: list):
    """Imprime resumen estadístico."""
    total = len(results)
    counts = {
        "VULNERABLE": 0,
        "PROBABLEMENTE_VULNERABLE": 0,
        "MITIGADO": 0,
        "NO_VULNERABLE": 0,
        "UNKNOWN": 0,
    }
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    print()
    print(colorize("  RESUMEN", "BOLD"))
    print(f"  {'─' * 50}")
    print(f"  Total hosts verificados:        {total}")
    print(colorize(f"  🔴 VULNERABLE:                  {counts['VULNERABLE']}", "RED"))
    print(colorize(f"  🟠 PROBABLEMENTE VULNERABLE:    {counts['PROBABLEMENTE_VULNERABLE']}", "YELLOW"))
    print(colorize(f"  🟡 MITIGADO:                    {counts['MITIGADO']}", "YELLOW"))
    print(colorize(f"  🟢 NO VULNERABLE:               {counts['NO_VULNERABLE']}", "GREEN"))
    print(f"  ⚪ DESCONOCIDO:                 {counts['UNKNOWN']}")
    print()

    if counts["VULNERABLE"] > 0 or counts["PROBABLEMENTE_VULNERABLE"] > 0:
        print(colorize("  ⚠️  ACCIÓN REQUERIDA - Ver recomendaciones por host arriba", "RED"))
        print()


def results_to_json(results: list) -> list:
    """Convierte resultados a formato JSON serializable."""
    output = []
    for r in results:
        output.append({
            "hostname": r.hostname,
            "kernel_version": r.kernel_version,
            "distro": r.distro,
            "distro_version": r.distro_version,
            "arch": r.arch,
            "algif_status": r.algif_status,
            "mitigation_modprobe": r.mitigation_modprobe,
            "mitigation_boot_param": r.mitigation_boot_param,
            "status": r.status,
            "details": r.details,
            "recommendations": r.recommendations,
        })
    return output
