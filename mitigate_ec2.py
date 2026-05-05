#!/usr/bin/env python3
"""
mitigate_ec2.py - Aplica mitigación automática a instancias EC2 vulnerables

Aplica la mitigación apropiada según el tipo de distribución:
  - Distros con módulo cargable (Ubuntu, Debian, SUSE, Amazon Linux): modprobe blacklist
  - Distros EL (RHEL, Rocky, CentOS, Oracle, Fedora): initcall_blacklist boot param

Requisitos:
  - Python 3.8+
  - boto3 (pip install boto3)
  - Credenciales AWS configuradas
  - SSM Agent activo en instancias
  - Permisos IAM para SSM SendCommand

Uso:
  python mitigate_ec2.py --region us-east-1
  python mitigate_ec2.py --all-regions --profile produccion
  python mitigate_ec2.py --instance-ids i-0abc123,i-0def456 --region us-east-1
  python mitigate_ec2.py --region us-east-1 --dry-run  # Solo simular
  python mitigate_ec2.py --region us-east-1 --json > mitigation_results.json
"""

import argparse
import json
import sys
import time
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.kernel_check import (
    is_el_distro,
    colorize,
    print_banner,
)

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("ERROR: boto3 no está instalado. Ejecuta: pip install boto3")
    sys.exit(1)


# Comando de mitigación para distros con módulo cargable
MITIGATION_MODULE = """
#!/bin/bash
set -e

echo "=== Aplicando mitigación modprobe para CVE-2026-31431 ==="

# Crear archivo de configuración modprobe
echo "# CVE-2026-31431 (Copy Fail) mitigation" | tee /etc/modprobe.d/disable-algif-aead-cve-2026-31431.conf
echo "install algif_aead /bin/false" | tee -a /etc/modprobe.d/disable-algif-aead-cve-2026-31431.conf

echo "✓ Archivo modprobe creado"

# Intentar descargar el módulo si está cargado
if lsmod | grep -q '^algif_aead '; then
    echo "Módulo algif_aead está cargado, intentando descargarlo..."
    rmmod algif_aead 2>/dev/null && echo "✓ Módulo descargado" || echo "⚠ No se pudo descargar (puede estar en uso, requiere reboot)"
else
    echo "✓ Módulo algif_aead no está cargado"
fi

# Verificar estado final
if grep -q '^algif_aead ' /proc/modules 2>/dev/null; then
    echo "STATUS=MITIGATED_REBOOT_REQUIRED"
    echo "⚠ Módulo aún cargado - REQUIERE REBOOT para activar mitigación"
else
    echo "STATUS=MITIGATED_ACTIVE"
    echo "✓ Mitigación ACTIVA - módulo bloqueado"
fi

echo "=== Mitigación completada ==="
"""

# Comando de mitigación para distros EL (kernel built-in)
MITIGATION_EL = """
#!/bin/bash
set -e

echo "=== Aplicando mitigación boot param para CVE-2026-31431 (EL distro) ==="

# Verificar si ya está aplicado
if grep -q 'initcall_blacklist=algif_aead_init' /proc/cmdline 2>/dev/null; then
    echo "✓ Mitigación ya está activa en boot params"
    echo "STATUS=ALREADY_MITIGATED"
    exit 0
fi

# Verificar si grubby está disponible
if ! command -v grubby &> /dev/null; then
    echo "ERROR: grubby no está disponible"
    echo "STATUS=ERROR_NO_GRUBBY"
    exit 1
fi

# Aplicar boot parameter
echo "Agregando initcall_blacklist=algif_aead_init a kernel boot params..."
grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"

echo "✓ Boot parameter agregado"
echo "STATUS=MITIGATED_REBOOT_REQUIRED"
echo "⚠ REQUIERE REBOOT para activar mitigación"

# Verificar que se aplicó
if grubby --info=ALL | grep -q 'initcall_blacklist=algif_aead_init'; then
    echo "✓ Verificación: boot param presente en configuración GRUB"
else
    echo "⚠ Advertencia: no se pudo verificar en configuración GRUB"
fi

echo "=== Mitigación completada - REBOOT REQUERIDO ==="
"""


def get_vulnerable_instances(ec2_client, ssm_client, region: str, instance_ids: list = None) -> list:
    """Obtiene lista de instancias vulnerables desde check_ec2.py."""
    import subprocess
    
    cmd = [sys.executable, "check_ec2.py", "--region", region, "--json"]
    if instance_ids:
        cmd.extend(["--instance-ids", ",".join(instance_ids)])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            # Filtrar solo vulnerables
            return [r for r in data if r.get("status") == "VULNERABLE"]
    except Exception as e:
        print(f"Error obteniendo instancias vulnerables: {e}")
    
    return []


def apply_mitigation_ssm(ssm_client, instance_id: str, distro: str, dry_run: bool = False) -> dict:
    """Aplica mitigación via SSM a una instancia."""
    result = {
        "instance_id": instance_id,
        "success": False,
        "status": "UNKNOWN",
        "message": "",
        "reboot_required": False,
    }
    
    if dry_run:
        result["success"] = True
        result["status"] = "DRY_RUN"
        result["message"] = f"[DRY RUN] Se aplicaría mitigación {'EL' if is_el_distro(distro) else 'modprobe'}"
        return result
    
    # Seleccionar comando según distribución
    if is_el_distro(distro):
        command = MITIGATION_EL
        mitigation_type = "boot_param"
    else:
        command = MITIGATION_MODULE
        mitigation_type = "modprobe"
    
    try:
        # Enviar comando
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
            TimeoutSeconds=120,
        )
        command_id = response["Command"]["CommandId"]
        
        # Esperar resultado
        for _ in range(30):
            time.sleep(4)
            try:
                invocation = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id,
                )
                
                if invocation["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
                    output = invocation.get("StandardOutputContent", "")
                    error = invocation.get("StandardErrorContent", "")
                    
                    if invocation["Status"] == "Success":
                        result["success"] = True
                        result["message"] = output
                        
                        # Determinar si requiere reboot
                        if "MITIGATED_REBOOT_REQUIRED" in output:
                            result["status"] = "MITIGATED_REBOOT_REQUIRED"
                            result["reboot_required"] = True
                        elif "MITIGATED_ACTIVE" in output:
                            result["status"] = "MITIGATED_ACTIVE"
                            result["reboot_required"] = False
                        elif "ALREADY_MITIGATED" in output:
                            result["status"] = "ALREADY_MITIGATED"
                            result["reboot_required"] = False
                        else:
                            result["status"] = "MITIGATED"
                            result["reboot_required"] = True  # Asumir reboot por seguridad
                    else:
                        result["success"] = False
                        result["status"] = "ERROR"
                        result["message"] = f"Comando falló: {error[:200]}"
                    
                    break
                    
            except ssm_client.exceptions.InvocationDoesNotExist:
                continue
            except ClientError as e:
                result["message"] = f"Error obteniendo resultado: {str(e)[:100]}"
                break
    
    except ClientError as e:
        result["message"] = f"Error enviando comando SSM: {str(e)[:100]}"
    except Exception as e:
        result["message"] = f"Error inesperado: {str(e)[:100]}"
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Aplica mitigación automática a instancias EC2 vulnerables a CVE-2026-31431",
    )
    parser.add_argument("--region", type=str, help="Región AWS")
    parser.add_argument("--profile", type=str, help="Perfil AWS")
    parser.add_argument("--all-regions", action="store_true", help="Todas las regiones")
    parser.add_argument("--instance-ids", type=str, help="IDs específicos separados por coma")
    parser.add_argument("--dry-run", action="store_true", help="Simular sin aplicar cambios")
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    parser.add_argument("--auto-reboot", action="store_true", help="Reiniciar automáticamente si es necesario (PELIGROSO)")
    
    args = parser.parse_args()
    
    if not args.json:
        print_banner()
        print(colorize("  APLICACIÓN DE MITIGACIÓN - Instancias EC2", "BOLD"))
        if args.dry_run:
            print(colorize("  MODO: DRY RUN (simulación, sin cambios reales)", "YELLOW"))
        print()
    
    # Sesión AWS
    try:
        session_kwargs = {}
        if args.profile:
            session_kwargs["profile_name"] = args.profile
        if args.region and not args.all_regions:
            session_kwargs["region_name"] = args.region
        
        session = boto3.Session(**session_kwargs)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        
        if not args.json:
            print(f"  Cuenta AWS: {identity['Account']}")
            print(f"  Identidad:  {identity['Arn']}")
            print()
    
    except NoCredentialsError:
        print(colorize("ERROR: No se encontraron credenciales AWS.", "RED"))
        sys.exit(1)
    except ClientError as e:
        print(colorize(f"ERROR: {e}", "RED"))
        sys.exit(1)
    
    # Regiones
    if args.all_regions:
        ec2_temp = session.client("ec2", region_name="us-east-1")
        regions = [r["RegionName"] for r in ec2_temp.describe_regions(AllRegions=False)["Regions"]]
    else:
        regions = [session.region_name or "us-east-1"]
    
    all_results = []
    
    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)
            ssm_client = session.client("ssm", region_name=region)
            
            if not args.json:
                print(f"  [{region}] Buscando instancias vulnerables...")
            
            # Obtener instancias vulnerables
            target_ids = None
            if args.instance_ids:
                target_ids = [i.strip() for i in args.instance_ids.split(",")]
            
            vulnerable = get_vulnerable_instances(ec2_client, ssm_client, region, target_ids)
            
            if not vulnerable:
                if not args.json:
                    print(f"  [{region}] No se encontraron instancias vulnerables")
                continue
            
            if not args.json:
                print(f"  [{region}] {len(vulnerable)} instancias vulnerables encontradas")
                print()
            
            # Aplicar mitigación a cada instancia
            for vuln in vulnerable:
                instance_id = vuln["hostname"].split()[0]  # Extraer ID
                distro = vuln.get("distro", "")
                
                if not args.json:
                    print(f"    Aplicando mitigación a {instance_id} ({distro})...")
                
                result = apply_mitigation_ssm(ssm_client, instance_id, distro, args.dry_run)
                result["region"] = region
                result["distro"] = distro
                result["hostname"] = vuln["hostname"]
                
                all_results.append(result)
                
                if not args.json:
                    if result["success"]:
                        status_color = "GREEN" if result["status"] == "MITIGATED_ACTIVE" else "YELLOW"
                        print(colorize(f"      ✓ {result['status']}", status_color))
                        if result["reboot_required"]:
                            print(colorize(f"      ⚠ REQUIERE REBOOT", "YELLOW"))
                    else:
                        print(colorize(f"      ✗ ERROR: {result['message'][:80]}", "RED"))
                    print()
                
                # Auto-reboot si se solicitó
                if args.auto_reboot and result["reboot_required"] and result["success"]:
                    if not args.json:
                        print(colorize(f"      Reiniciando {instance_id}...", "YELLOW"))
                    try:
                        ec2_client.reboot_instances(InstanceIds=[instance_id])
                        result["rebooted"] = True
                        if not args.json:
                            print(colorize(f"      ✓ Reboot iniciado", "GREEN"))
                    except ClientError as e:
                        result["reboot_error"] = str(e)
                        if not args.json:
                            print(colorize(f"      ✗ Error reiniciando: {e}", "RED"))
        
        except Exception as e:
            if not args.json:
                print(colorize(f"  [{region}] Error: {e}", "RED"))
    
    # Output
    if args.json:
        print(json.dumps(all_results, indent=2, ensure_ascii=False))
    else:
        print()
        print(colorize("=" * 80, "CYAN"))
        print(colorize("  RESUMEN DE MITIGACIÓN", "BOLD"))
        print(colorize("=" * 80, "CYAN"))
        
        total = len(all_results)
        success = sum(1 for r in all_results if r["success"])
        reboot_required = sum(1 for r in all_results if r.get("reboot_required", False))
        
        print(f"\n  Total instancias procesadas: {total}")
        print(colorize(f"  ✓ Mitigación exitosa:        {success}", "GREEN"))
        print(colorize(f"  ✗ Errores:                   {total - success}", "RED"))
        print(colorize(f"  ⚠ Requieren reboot:          {reboot_required}", "YELLOW"))
        
        if reboot_required > 0 and not args.auto_reboot:
            print()
            print(colorize("  ACCIÓN REQUERIDA:", "BOLD"))
            print("  Las siguientes instancias requieren reboot para activar la mitigación:")
            for r in all_results:
                if r.get("reboot_required", False):
                    print(f"    - {r['instance_id']} ({r.get('hostname', 'N/A')})")
            print()
            print("  Para reiniciar automáticamente, usa: --auto-reboot")
        
        print()


if __name__ == "__main__":
    main()
