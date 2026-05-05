#!/usr/bin/env python3
"""
update_kernel_ec2.py - Actualiza kernel en instancias EC2 cuando el parche esté disponible

Verifica si hay actualizaciones de kernel disponibles y las aplica automáticamente.
Soporta diferentes distribuciones (Amazon Linux, Ubuntu, RHEL, etc.)

Requisitos:
  - Python 3.8+
  - boto3 (pip install boto3)
  - Credenciales AWS configuradas
  - SSM Agent activo en instancias
  - Permisos IAM para SSM SendCommand

Uso:
  python update_kernel_ec2.py --region us-east-1
  python update_kernel_ec2.py --all-regions --profile produccion
  python update_kernel_ec2.py --instance-ids i-0abc123,i-0def456 --region us-east-1
  python update_kernel_ec2.py --region us-east-1 --check-only  # Solo verificar, no actualizar
  python update_kernel_ec2.py --region us-east-1 --auto-reboot  # Reiniciar automáticamente
  python update_kernel_ec2.py --region us-east-1 --json > update_results.json
"""

import argparse
import json
import sys
import time
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.kernel_check import (
    colorize,
    print_banner,
)

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("ERROR: boto3 no está instalado. Ejecuta: pip install boto3")
    sys.exit(1)


# Comandos de actualización por distribución
UPDATE_COMMANDS = {
    "amzn2023": """
#!/bin/bash
set -e
echo "=== Actualizando kernel en Amazon Linux 2023 ==="

# Verificar actualizaciones disponibles
echo "Verificando actualizaciones de kernel..."
UPDATES=$(dnf check-update kernel --quiet 2>/dev/null | grep -c '^kernel' || echo "0")

if [ "$UPDATES" -eq "0" ]; then
    echo "STATUS=NO_UPDATES"
    echo "✓ No hay actualizaciones de kernel disponibles"
    exit 0
fi

echo "Actualizaciones de kernel disponibles: $UPDATES"
echo "UPDATES_AVAILABLE=YES"

# Actualizar kernel
echo "Instalando actualización de kernel..."
dnf update -y kernel

# Verificar nueva versión
NEW_KERNEL=$(rpm -q kernel --last | head -1 | awk '{print $1}')
echo "Nueva versión instalada: $NEW_KERNEL"

echo "STATUS=UPDATED_REBOOT_REQUIRED"
echo "✓ Kernel actualizado - REQUIERE REBOOT"
""",
    
    "amzn2": """
#!/bin/bash
set -e
echo "=== Actualizando kernel en Amazon Linux 2 ==="

# Verificar actualizaciones
echo "Verificando actualizaciones de kernel..."
UPDATES=$(yum check-update kernel --quiet 2>/dev/null | grep -c '^kernel' || echo "0")

if [ "$UPDATES" -eq "0" ]; then
    echo "STATUS=NO_UPDATES"
    echo "✓ No hay actualizaciones de kernel disponibles"
    exit 0
fi

echo "UPDATES_AVAILABLE=YES"

# Actualizar
echo "Instalando actualización de kernel..."
yum update -y kernel

NEW_KERNEL=$(rpm -q kernel --last | head -1 | awk '{print $1}')
echo "Nueva versión instalada: $NEW_KERNEL"

echo "STATUS=UPDATED_REBOOT_REQUIRED"
echo "✓ Kernel actualizado - REQUIERE REBOOT"
""",
    
    "ubuntu": """
#!/bin/bash
set -e
echo "=== Actualizando kernel en Ubuntu ==="

# Actualizar lista de paquetes
echo "Actualizando lista de paquetes..."
apt-get update -qq

# Verificar actualizaciones de kernel
echo "Verificando actualizaciones de kernel..."
UPDATES=$(apt-cache policy linux-image-generic | grep -c 'Candidate:' || echo "0")

if apt-cache policy linux-image-generic | grep -q 'Candidate: (none)'; then
    echo "STATUS=NO_UPDATES"
    echo "✓ No hay actualizaciones de kernel disponibles"
    exit 0
fi

CURRENT=$(dpkg -l | grep 'linux-image-[0-9]' | grep '^ii' | awk '{print $3}' | sort -V | tail -1)
CANDIDATE=$(apt-cache policy linux-image-generic | grep 'Candidate:' | awk '{print $2}')

echo "Versión actual: $CURRENT"
echo "Versión candidata: $CANDIDATE"

if [ "$CURRENT" = "$CANDIDATE" ]; then
    echo "STATUS=NO_UPDATES"
    echo "✓ Kernel ya está actualizado"
    exit 0
fi

echo "UPDATES_AVAILABLE=YES"

# Actualizar kernel
echo "Instalando actualización de kernel..."
DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-generic linux-headers-generic

echo "STATUS=UPDATED_REBOOT_REQUIRED"
echo "✓ Kernel actualizado - REQUIERE REBOOT"
""",
    
    "rhel": """
#!/bin/bash
set -e
echo "=== Actualizando kernel en RHEL/CentOS/Rocky/AlmaLinux ==="

# Verificar actualizaciones
echo "Verificando actualizaciones de kernel..."
UPDATES=$(yum check-update kernel --quiet 2>/dev/null | grep -c '^kernel' || echo "0")

if [ "$UPDATES" -eq "0" ]; then
    echo "STATUS=NO_UPDATES"
    echo "✓ No hay actualizaciones de kernel disponibles"
    exit 0
fi

echo "UPDATES_AVAILABLE=YES"

# Actualizar
echo "Instalando actualización de kernel..."
yum update -y kernel

NEW_KERNEL=$(rpm -q kernel --last | head -1 | awk '{print $1}')
echo "Nueva versión instalada: $NEW_KERNEL"

echo "STATUS=UPDATED_REBOOT_REQUIRED"
echo "✓ Kernel actualizado - REQUIERE REBOOT"
""",
    
    "debian": """
#!/bin/bash
set -e
echo "=== Actualizando kernel en Debian ==="

# Actualizar lista
apt-get update -qq

# Verificar actualizaciones
echo "Verificando actualizaciones de kernel..."
UPDATES=$(apt-cache policy linux-image-amd64 | grep -c 'Candidate:' || echo "0")

if apt-cache policy linux-image-amd64 | grep -q 'Candidate: (none)'; then
    echo "STATUS=NO_UPDATES"
    echo "✓ No hay actualizaciones de kernel disponibles"
    exit 0
fi

echo "UPDATES_AVAILABLE=YES"

# Actualizar
echo "Instalando actualización de kernel..."
DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-amd64 linux-headers-amd64

echo "STATUS=UPDATED_REBOOT_REQUIRED"
echo "✓ Kernel actualizado - REQUIERE REBOOT"
""",
    
    "suse": """
#!/bin/bash
set -e
echo "=== Actualizando kernel en SUSE ==="

# Verificar actualizaciones
echo "Verificando actualizaciones de kernel..."
zypper refresh -q

UPDATES=$(zypper list-updates | grep -c '^v | kernel-default' || echo "0")

if [ "$UPDATES" -eq "0" ]; then
    echo "STATUS=NO_UPDATES"
    echo "✓ No hay actualizaciones de kernel disponibles"
    exit 0
fi

echo "UPDATES_AVAILABLE=YES"

# Actualizar
echo "Instalando actualización de kernel..."
zypper update -y kernel-default

echo "STATUS=UPDATED_REBOOT_REQUIRED"
echo "✓ Kernel actualizado - REQUIERE REBOOT"
""",
}

# Comando de verificación (solo check)
CHECK_COMMAND = """
#!/bin/bash
echo "=== Verificando actualizaciones de kernel ==="
echo "Distribución: $(cat /etc/os-release | grep '^ID=' | cut -d= -f2 | tr -d '"')"
echo "Kernel actual: $(uname -r)"

# Detectar distribución y verificar
if [ -f /etc/os-release ]; then
    . /etc/os-release
    
    case "$ID" in
        amzn)
            if [ "$VERSION_ID" = "2023" ]; then
                dnf check-update kernel --quiet 2>/dev/null | grep '^kernel' && echo "UPDATES=YES" || echo "UPDATES=NO"
            else
                yum check-update kernel --quiet 2>/dev/null | grep '^kernel' && echo "UPDATES=YES" || echo "UPDATES=NO"
            fi
            ;;
        ubuntu|debian)
            apt-get update -qq 2>/dev/null
            apt-cache policy linux-image-generic 2>/dev/null | grep -v '(none)' | grep 'Candidate:' && echo "UPDATES=YES" || echo "UPDATES=NO"
            ;;
        rhel|centos|rocky|almalinux|ol|fedora)
            yum check-update kernel --quiet 2>/dev/null | grep '^kernel' && echo "UPDATES=YES" || echo "UPDATES=NO"
            ;;
        sles|opensuse*)
            zypper refresh -q 2>/dev/null
            zypper list-updates 2>/dev/null | grep 'kernel-default' && echo "UPDATES=YES" || echo "UPDATES=NO"
            ;;
        *)
            echo "UPDATES=UNKNOWN"
            ;;
    esac
fi

echo "=== Verificación completada ==="
"""


def get_update_command(distro: str) -> str:
    """Obtiene el comando de actualización apropiado para la distribución."""
    # Mapear distros a comandos
    if distro.startswith("amzn2023"):
        return UPDATE_COMMANDS["amzn2023"]
    elif distro.startswith("amzn"):
        return UPDATE_COMMANDS["amzn2"]
    elif distro.startswith("ubuntu"):
        return UPDATE_COMMANDS["ubuntu"]
    elif distro in ["rhel", "centos", "rocky", "alma", "oracle", "fedora"]:
        return UPDATE_COMMANDS["rhel"]
    elif distro.startswith("debian"):
        return UPDATE_COMMANDS["debian"]
    elif distro.startswith("suse"):
        return UPDATE_COMMANDS["suse"]
    else:
        return UPDATE_COMMANDS["rhel"]  # Default genérico


def check_or_update_kernel(ssm_client, instance_id: str, distro: str, check_only: bool = False) -> dict:
    """Verifica o actualiza el kernel de una instancia."""
    result = {
        "instance_id": instance_id,
        "success": False,
        "status": "UNKNOWN",
        "message": "",
        "updates_available": False,
        "reboot_required": False,
    }
    
    # Seleccionar comando
    if check_only:
        command = CHECK_COMMAND
    else:
        command = get_update_command(distro)
    
    try:
        # Enviar comando
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
            TimeoutSeconds=600,  # 10 minutos para actualizaciones
        )
        command_id = response["Command"]["CommandId"]
        
        # Esperar resultado
        for _ in range(60):
            time.sleep(10)
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
                        
                        # Parsear estado
                        if "UPDATES=YES" in output or "UPDATES_AVAILABLE=YES" in output:
                            result["updates_available"] = True
                        
                        if "STATUS=NO_UPDATES" in output:
                            result["status"] = "NO_UPDATES"
                        elif "STATUS=UPDATED_REBOOT_REQUIRED" in output:
                            result["status"] = "UPDATED_REBOOT_REQUIRED"
                            result["reboot_required"] = True
                        elif "UPDATES=YES" in output:
                            result["status"] = "UPDATES_AVAILABLE"
                            result["updates_available"] = True
                        elif "UPDATES=NO" in output:
                            result["status"] = "NO_UPDATES"
                        else:
                            result["status"] = "COMPLETED"
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


def get_target_instances(ec2_client, ssm_client, region: str, instance_ids: list = None) -> list:
    """Obtiene instancias objetivo (vulnerables o mitigadas)."""
    import subprocess
    
    cmd = [sys.executable, "check_ec2.py", "--region", region, "--json"]
    if instance_ids:
        cmd.extend(["--instance-ids", ",".join(instance_ids)])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            # Incluir vulnerables y mitigados (ambos necesitan actualización)
            return [r for r in data if r.get("status") in ["VULNERABLE", "MITIGADO"]]
    except Exception as e:
        print(f"Error obteniendo instancias: {e}")
    
    return []


def main():
    parser = argparse.ArgumentParser(
        description="Actualiza kernel en instancias EC2 cuando el parche esté disponible",
    )
    parser.add_argument("--region", type=str, help="Región AWS")
    parser.add_argument("--profile", type=str, help="Perfil AWS")
    parser.add_argument("--all-regions", action="store_true", help="Todas las regiones")
    parser.add_argument("--instance-ids", type=str, help="IDs específicos separados por coma")
    parser.add_argument("--check-only", action="store_true", help="Solo verificar actualizaciones, no instalar")
    parser.add_argument("--auto-reboot", action="store_true", help="Reiniciar automáticamente después de actualizar")
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    
    args = parser.parse_args()
    
    if not args.json:
        print_banner()
        print(colorize("  ACTUALIZACIÓN DE KERNEL - Instancias EC2", "BOLD"))
        if args.check_only:
            print(colorize("  MODO: Solo verificación (no se instalarán actualizaciones)", "YELLOW"))
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
                print(f"  [{region}] Buscando instancias objetivo...")
            
            # Obtener instancias
            target_ids = None
            if args.instance_ids:
                target_ids = [i.strip() for i in args.instance_ids.split(",")]
            
            targets = get_target_instances(ec2_client, ssm_client, region, target_ids)
            
            if not targets:
                if not args.json:
                    print(f"  [{region}] No se encontraron instancias objetivo")
                continue
            
            if not args.json:
                print(f"  [{region}] {len(targets)} instancias encontradas")
                print()
            
            # Procesar cada instancia
            for target in targets:
                instance_id = target["hostname"].split()[0]
                distro = target.get("distro", "")
                
                if not args.json:
                    action = "Verificando" if args.check_only else "Actualizando"
                    print(f"    {action} {instance_id} ({distro})...")
                
                result = check_or_update_kernel(ssm_client, instance_id, distro, args.check_only)
                result["region"] = region
                result["distro"] = distro
                result["hostname"] = target["hostname"]
                
                all_results.append(result)
                
                if not args.json:
                    if result["success"]:
                        if result["status"] == "NO_UPDATES":
                            print(colorize(f"      ✓ No hay actualizaciones disponibles", "GREEN"))
                        elif result["status"] == "UPDATES_AVAILABLE":
                            print(colorize(f"      ⚠ Actualizaciones disponibles (usa sin --check-only para instalar)", "YELLOW"))
                        elif result["status"] == "UPDATED_REBOOT_REQUIRED":
                            print(colorize(f"      ✓ Kernel actualizado - REQUIERE REBOOT", "YELLOW"))
                        else:
                            print(colorize(f"      ✓ {result['status']}", "GREEN"))
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
        print(colorize("  RESUMEN DE ACTUALIZACIÓN", "BOLD"))
        print(colorize("=" * 80, "CYAN"))
        
        total = len(all_results)
        success = sum(1 for r in all_results if r["success"])
        updates_available = sum(1 for r in all_results if r.get("updates_available", False))
        updated = sum(1 for r in all_results if r.get("status") == "UPDATED_REBOOT_REQUIRED")
        no_updates = sum(1 for r in all_results if r.get("status") == "NO_UPDATES")
        reboot_required = sum(1 for r in all_results if r.get("reboot_required", False))
        
        print(f"\n  Total instancias procesadas: {total}")
        print(colorize(f"  ✓ Procesadas exitosamente:   {success}", "GREEN"))
        print(colorize(f"  ⚠ Actualizaciones disponibles: {updates_available}", "YELLOW"))
        print(colorize(f"  ✓ Kernels actualizados:      {updated}", "GREEN"))
        print(f"  ✓ Ya actualizadas:           {no_updates}")
        print(colorize(f"  ⚠ Requieren reboot:          {reboot_required}", "YELLOW"))
        
        if reboot_required > 0 and not args.auto_reboot:
            print()
            print(colorize("  ACCIÓN REQUERIDA:", "BOLD"))
            print("  Las siguientes instancias requieren reboot para aplicar el nuevo kernel:")
            for r in all_results:
                if r.get("reboot_required", False):
                    print(f"    - {r['instance_id']} ({r.get('hostname', 'N/A')})")
            print()
            print("  Para reiniciar automáticamente, usa: --auto-reboot")
        
        print()


if __name__ == "__main__":
    main()
