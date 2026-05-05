#!/usr/bin/env python3
"""
check_local.py - Verifica el equipo LOCAL contra CVE-2026-31431 (Copy Fail)

Ejecuta la verificación directamente en la máquina donde se corre el script.
Ideal para verificar tu propia estación de trabajo Linux, WSL, o un servidor
al que ya tienes acceso directo.

Requisitos:
  - Python 3.8+
  - Ejecutar en un sistema Linux (o WSL)

Uso:
  python check_local.py
  python check_local.py --json
  python check_local.py --mitigate  # Aplica mitigación (requiere sudo)
"""

import argparse
import json
import os
import platform
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.kernel_check import (
    CHECK_COMMANDS,
    VulnerabilityResult,
    evaluate_vulnerability,
    is_el_distro,
    is_kernel_vulnerable,
    parse_check_output,
    print_banner,
    print_results_table,
    print_summary,
    results_to_json,
    colorize,
)


def run_local_check() -> str:
    """Ejecuta los comandos de verificación localmente."""
    try:
        result = subprocess.run(
            ["bash", "-c", CHECK_COMMANDS],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError:
        # Intentar con sh
        try:
            result = subprocess.run(
                ["sh", "-c", CHECK_COMMANDS],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout
        except Exception:
            return ""
    except Exception:
        return ""


def apply_mitigation(distro_key: str) -> bool:
    """Aplica la mitigación apropiada según la distribución."""
    if os.geteuid() != 0:
        print(colorize("  ERROR: Se requiere ejecutar como root (sudo) para aplicar mitigación.", "RED"))
        return False

    if is_el_distro(distro_key):
        # EL distros: kernel built-in, usar initcall_blacklist
        print("  Distribución EL detectada (kernel built-in). Usando initcall_blacklist...")
        try:
            subprocess.run(
                ["grubby", "--update-kernel=ALL", "--args=initcall_blacklist=algif_aead_init"],
                check=True,
            )
            print(colorize("  ✓ Boot parameter agregado. REQUIERE REBOOT para activar.", "YELLOW"))
            print("    Ejecuta: sudo reboot")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(colorize(f"  ERROR: {e}", "RED"))
            print("  Alternativa manual:")
            print('    Agregar "initcall_blacklist=algif_aead_init" a GRUB_CMDLINE_LINUX en /etc/default/grub')
            print("    Luego: grub2-mkconfig -o /boot/grub2/grub.cfg && reboot")
            return False
    else:
        # Distros con módulo cargable
        print("  Aplicando mitigación modprobe...")
        try:
            # Crear archivo modprobe
            with open("/etc/modprobe.d/disable-algif-aead-cve-2026-31431.conf", "w") as f:
                f.write("# CVE-2026-31431 (Copy Fail) mitigation\n")
                f.write("install algif_aead /bin/false\n")
            print("  ✓ Archivo /etc/modprobe.d/disable-algif-aead-cve-2026-31431.conf creado")

            # Intentar descargar módulo
            subprocess.run(["rmmod", "algif_aead"], capture_output=True)

            # Verificar
            result = subprocess.run(
                ["bash", "-c", "grep -c '^algif_aead ' /proc/modules"],
                capture_output=True,
                text=True,
            )
            if result.stdout.strip() == "0":
                print(colorize("  ✓ Módulo algif_aead descargado exitosamente. Mitigación ACTIVA.", "GREEN"))
            else:
                print(colorize("  ⚠ Módulo aún cargado (puede estar en uso). Requiere reboot.", "YELLOW"))
                print("    Ejecuta: sudo reboot")

            return True

        except PermissionError:
            print(colorize("  ERROR: Permisos insuficientes.", "RED"))
            return False
        except Exception as e:
            print(colorize(f"  ERROR: {e}", "RED"))
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Verifica el equipo LOCAL contra CVE-2026-31431 (Copy Fail)",
    )
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    parser.add_argument("--mitigate", action="store_true", help="Aplicar mitigación (requiere sudo)")

    args = parser.parse_args()

    # Verificar que estamos en Linux
    if platform.system() != "Linux":
        if not args.json:
            print_banner()
            print(colorize("  Este script debe ejecutarse en un sistema Linux.", "YELLOW"))
            print(f"  Sistema detectado: {platform.system()}")
            print()
            if platform.system() == "Windows":
                print("  Para Windows con WSL:")
                print("    wsl python3 check_local.py")
            elif platform.system() == "Darwin":
                print("  macOS no usa kernel Linux y no es vulnerable a CVE-2026-31431.")
        else:
            result = VulnerabilityResult(
                hostname=platform.node(),
                status="NO_VULNERABLE",
                details=f"Sistema {platform.system()} - no usa kernel Linux",
            )
            print(json.dumps(results_to_json([result]), indent=2, ensure_ascii=False))
        sys.exit(0)

    if not args.json:
        print_banner()
        print("  Modo: Verificación LOCAL")
        print(f"  Hostname: {platform.node()}")
        print()

    # Ejecutar verificación
    output = run_local_check()

    if not output:
        if not args.json:
            print(colorize("  ERROR: No se pudo ejecutar la verificación.", "RED"))
            print("  Verifica que tienes bash disponible y permisos de lectura en /proc y /boot.")
        sys.exit(1)

    result = parse_check_output(output, platform.node())

    # Output
    if args.json:
        print(json.dumps(results_to_json([result]), indent=2, ensure_ascii=False))
    else:
        print(f"  Kernel:       {result.kernel_version}")
        print(f"  Distribución: {result.distro}")
        print(f"  Arquitectura: {result.arch}")
        print(f"  Módulo:       {result.algif_status}")
        print(f"  Mitigación:   {'Sí' if result.is_mitigated else 'No'}")
        print()

        status_map = {
            "VULNERABLE": ("RED", "⚠️  SISTEMA VULNERABLE A CVE-2026-31431"),
            "PROBABLEMENTE_VULNERABLE": ("YELLOW", "⚠️  SISTEMA PROBABLEMENTE VULNERABLE"),
            "MITIGADO": ("YELLOW", "✓ SISTEMA MITIGADO (pero actualizar kernel cuando sea posible)"),
            "NO_VULNERABLE": ("GREEN", "✓ SISTEMA NO VULNERABLE"),
            "UNKNOWN": ("RESET", "? NO SE PUDO DETERMINAR"),
        }
        color, msg = status_map.get(result.status, ("RESET", result.status))
        print(f"  {colorize(msg, color)}")
        print()

        if result.details:
            print(f"  Detalles: {result.details}")
            print()

        if result.recommendations:
            print(colorize("  Recomendaciones:", "BOLD"))
            for rec in result.recommendations:
                print(f"    • {rec}")
            print()

        # Aplicar mitigación si se solicitó
        if args.mitigate:
            if result.status == "VULNERABLE":
                print(colorize("  Aplicando mitigación...", "BOLD"))
                apply_mitigation(result.distro)
            elif result.status == "MITIGADO":
                print("  El sistema ya tiene mitigación aplicada.")
            elif result.status == "NO_VULNERABLE":
                print("  El sistema no es vulnerable, no se requiere mitigación.")
        elif result.status == "VULNERABLE":
            print("  Para aplicar mitigación automáticamente:")
            print("    sudo python3 check_local.py --mitigate")
            print()


if __name__ == "__main__":
    main()
