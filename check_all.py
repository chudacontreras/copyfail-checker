#!/usr/bin/env python3
"""
check_all.py - Script unificado que ejecuta todas las verificaciones disponibles.

Ejecuta secuencialmente: local, EC2, EKS, ECS y opcionalmente SSH.
Genera un reporte consolidado.

Uso:
  python check_all.py --region us-east-1
  python check_all.py --all-regions --profile prod --ssh-hosts hosts.txt
  python check_all.py --region us-east-1 --json > reporte_completo.json
"""

import argparse
import json
import os
import platform
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.kernel_check import (
    print_banner,
    print_results_table,
    print_summary,
    results_to_json,
    colorize,
)


def run_script(script_name: str, extra_args: list) -> tuple:
    """Ejecuta un sub-script y captura su salida JSON."""
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), script_name)

    if not os.path.exists(script_path):
        return [], f"Script no encontrado: {script_name}"

    cmd = [sys.executable, script_path, "--json"] + extra_args

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            return data, None
        else:
            return [], result.stderr[:200] if result.stderr else "Sin resultados"
    except subprocess.TimeoutExpired:
        return [], "Timeout (10 min)"
    except json.JSONDecodeError:
        return [], "Error parseando JSON de salida"
    except Exception as e:
        return [], str(e)[:100]


def main():
    parser = argparse.ArgumentParser(
        description="Verificación unificada CVE-2026-31431 (Copy Fail) - Todos los entornos",
    )
    parser.add_argument("--region", type=str, help="Región AWS")
    parser.add_argument("--profile", type=str, help="Perfil AWS")
    parser.add_argument("--all-regions", action="store_true", help="Todas las regiones AWS")
    parser.add_argument("--ssh-hosts", type=str, help="Archivo de hosts SSH")
    parser.add_argument("--ssh-key", type=str, help="Clave SSH para hosts remotos")
    parser.add_argument("--ssh-user", type=str, default="root", help="Usuario SSH")
    parser.add_argument("--skip-local", action="store_true", help="Saltar verificación local")
    parser.add_argument("--skip-aws", action="store_true", help="Saltar verificaciones AWS")
    parser.add_argument("--json", action="store_true", help="Salida JSON consolidada")

    args = parser.parse_args()

    if not args.json:
        print_banner()
        print(colorize("  VERIFICACIÓN UNIFICADA - Todos los entornos", "BOLD"))
        print()

    all_results = {
        "local": [],
        "ec2": [],
        "eks": [],
        "ecs": [],
        "ssh": [],
    }
    errors = {}

    # AWS args comunes
    aws_args = []
    if args.region:
        aws_args.extend(["--region", args.region])
    if args.profile:
        aws_args.extend(["--profile", args.profile])
    if args.all_regions:
        aws_args.append("--all-regions")

    # 1. Local
    if not args.skip_local and platform.system() == "Linux":
        if not args.json:
            print("  [1/5] Verificando equipo local...")
        data, err = run_script("check_local.py", [])
        if err:
            errors["local"] = err
        all_results["local"] = data

    # 2. EC2
    if not args.skip_aws:
        if not args.json:
            print("  [2/5] Verificando instancias EC2...")
        data, err = run_script("check_ec2.py", aws_args)
        if err:
            errors["ec2"] = err
        all_results["ec2"] = data

        # 3. EKS
        if not args.json:
            print("  [3/5] Verificando nodos EKS...")
        data, err = run_script("check_eks.py", aws_args)
        if err:
            errors["eks"] = err
        all_results["eks"] = data

        # 4. ECS
        if not args.json:
            print("  [4/5] Verificando instancias ECS...")
        data, err = run_script("check_ecs.py", aws_args)
        if err:
            errors["ecs"] = err
        all_results["ecs"] = data

    # 5. SSH
    if args.ssh_hosts:
        if not args.json:
            print("  [5/5] Verificando hosts SSH...")
        ssh_args = ["--hosts", args.ssh_hosts, "--user", args.ssh_user]
        if args.ssh_key:
            ssh_args.extend(["--key", args.ssh_key])
        data, err = run_script("check_ssh.py", ssh_args)
        if err:
            errors["ssh"] = err
        all_results["ssh"] = data

    # Consolidar
    if args.json:
        output = {
            "results": all_results,
            "errors": errors,
            "summary": {
                "total": sum(len(v) for v in all_results.values()),
                "vulnerable": sum(
                    1 for v in all_results.values() for r in v if r.get("status") == "VULNERABLE"
                ),
                "probably_vulnerable": sum(
                    1 for v in all_results.values()
                    for r in v
                    if r.get("status") == "PROBABLEMENTE_VULNERABLE"
                ),
                "mitigated": sum(
                    1 for v in all_results.values() for r in v if r.get("status") == "MITIGADO"
                ),
                "not_vulnerable": sum(
                    1 for v in all_results.values() for r in v if r.get("status") == "NO_VULNERABLE"
                ),
                "unknown": sum(
                    1 for v in all_results.values() for r in v if r.get("status") == "UNKNOWN"
                ),
            },
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print()
        print(colorize("=" * 80, "CYAN"))
        print(colorize("  REPORTE CONSOLIDADO", "BOLD"))
        print(colorize("=" * 80, "CYAN"))

        total = sum(len(v) for v in all_results.values())
        vulnerable = sum(
            1 for v in all_results.values() for r in v if r.get("status") == "VULNERABLE"
        )
        prob_vuln = sum(
            1 for v in all_results.values()
            for r in v
            if r.get("status") == "PROBABLEMENTE_VULNERABLE"
        )
        mitigated = sum(
            1 for v in all_results.values() for r in v if r.get("status") == "MITIGADO"
        )
        not_vuln = sum(
            1 for v in all_results.values() for r in v if r.get("status") == "NO_VULNERABLE"
        )
        unknown = sum(
            1 for v in all_results.values() for r in v if r.get("status") == "UNKNOWN"
        )

        print(f"\n  Total hosts verificados: {total}")
        print(f"    Local:  {len(all_results['local'])}")
        print(f"    EC2:    {len(all_results['ec2'])}")
        print(f"    EKS:    {len(all_results['eks'])}")
        print(f"    ECS:    {len(all_results['ecs'])}")
        print(f"    SSH:    {len(all_results['ssh'])}")
        print()
        print(colorize(f"  🔴 VULNERABLE:               {vulnerable}", "RED"))
        print(colorize(f"  🟠 PROBABLEMENTE VULNERABLE:  {prob_vuln}", "YELLOW"))
        print(colorize(f"  🟡 MITIGADO:                  {mitigated}", "YELLOW"))
        print(colorize(f"  🟢 NO VULNERABLE:             {not_vuln}", "GREEN"))
        print(f"  ⚪ DESCONOCIDO:               {unknown}")

        if errors:
            print()
            print(colorize("  Errores:", "YELLOW"))
            for source, err in errors.items():
                print(f"    {source}: {err}")

        print()


if __name__ == "__main__":
    main()
