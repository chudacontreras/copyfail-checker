#!/usr/bin/env python3
"""
update_kernel_ssh.py - Actualiza kernel en hosts remotos via SSH

Verifica y aplica actualizaciones de kernel en servidores remotos.
Soporta diferentes distribuciones Linux.

Requisitos:
  - Python 3.8+
  - paramiko (pip install paramiko)
  - Acceso SSH con clave privada a los hosts

Uso:
  python update_kernel_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa
  python update_kernel_ssh.py --host 192.168.1.100 --user admin --key ~/.ssh/mi_clave
  python update_kernel_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --check-only
  python update_kernel_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --json > results.json
"""

import argparse
import json
import os
import sys
import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.kernel_check import (
    colorize,
    print_banner,
)

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko no está instalado. Ejecuta: pip install paramiko")
    sys.exit(1)


# Comandos de actualización (mismos que en update_kernel_ec2.py)
UPDATE_COMMANDS = {
    "amzn2023": """
#!/bin/bash
set -e
echo "=== Actualizando kernel en Amazon Linux 2023 ==="
UPDATES=$(sudo dnf check-update kernel --quiet 2>/dev/null | grep -c '^kernel' || echo "0")
if [ "$UPDATES" -eq "0" ]; then
    echo "STATUS=NO_UPDATES"
    echo "✓ No hay actualizaciones de kernel disponibles"
    exit 0
fi
echo "UPDATES_AVAILABLE=YES"
echo "Instalando actualización de kernel..."
sudo dnf update -y kernel
NEW_KERNEL=$(rpm -q kernel --last | head -1 | awk '{print $1}')
echo "Nueva versión instalada: $NEW_KERNEL"
echo "STATUS=UPDATED_REBOOT_REQUIRED"
echo "✓ Kernel actualizado - REQUIERE REBOOT"
""",
    
    "amzn2": """
#!/bin/bash
set -e
echo "=== Actualizando kernel en Amazon Linux 2 ==="
UPDATES=$(sudo yum check-update kernel --quiet 2>/dev/null | grep -c '^kernel' || echo "0")
if [ "$UPDATES" -eq "0" ]; then
    echo "STATUS=NO_UPDATES"
    exit 0
fi
echo "UPDATES_AVAILABLE=YES"
sudo yum update -y kernel
echo "STATUS=UPDATED_REBOOT_REQUIRED"
""",
    
    "ubuntu": """
#!/bin/bash
set -e
echo "=== Actualizando kernel en Ubuntu ==="
sudo apt-get update -qq
if apt-cache policy linux-image-generic | grep -q 'Candidate: (none)'; then
    echo "STATUS=NO_UPDATES"
    exit 0
fi
echo "UPDATES_AVAILABLE=YES"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-generic linux-headers-generic
echo "STATUS=UPDATED_REBOOT_REQUIRED"
""",
    
    "rhel": """
#!/bin/bash
set -e
echo "=== Actualizando kernel en RHEL/CentOS/Rocky/AlmaLinux ==="
UPDATES=$(sudo yum check-update kernel --quiet 2>/dev/null | grep -c '^kernel' || echo "0")
if [ "$UPDATES" -eq "0" ]; then
    echo "STATUS=NO_UPDATES"
    exit 0
fi
echo "UPDATES_AVAILABLE=YES"
sudo yum update -y kernel
echo "STATUS=UPDATED_REBOOT_REQUIRED"
""",
    
    "debian": """
#!/bin/bash
set -e
echo "=== Actualizando kernel en Debian ==="
sudo apt-get update -qq
if apt-cache policy linux-image-amd64 | grep -q 'Candidate: (none)'; then
    echo "STATUS=NO_UPDATES"
    exit 0
fi
echo "UPDATES_AVAILABLE=YES"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-amd64 linux-headers-amd64
echo "STATUS=UPDATED_REBOOT_REQUIRED"
""",
    
    "suse": """
#!/bin/bash
set -e
echo "=== Actualizando kernel en SUSE ==="
sudo zypper refresh -q
UPDATES=$(zypper list-updates | grep -c '^v | kernel-default' || echo "0")
if [ "$UPDATES" -eq "0" ]; then
    echo "STATUS=NO_UPDATES"
    exit 0
fi
echo "UPDATES_AVAILABLE=YES"
sudo zypper update -y kernel-default
echo "STATUS=UPDATED_REBOOT_REQUIRED"
""",
}

CHECK_COMMAND = """
#!/bin/bash
echo "=== Verificando actualizaciones de kernel ==="
echo "Kernel actual: $(uname -r)"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        amzn)
            if [ "$VERSION_ID" = "2023" ]; then
                sudo dnf check-update kernel --quiet 2>/dev/null | grep '^kernel' && echo "UPDATES=YES" || echo "UPDATES=NO"
            else
                sudo yum check-update kernel --quiet 2>/dev/null | grep '^kernel' && echo "UPDATES=YES" || echo "UPDATES=NO"
            fi
            ;;
        ubuntu|debian)
            sudo apt-get update -qq 2>/dev/null
            apt-cache policy linux-image-generic 2>/dev/null | grep -v '(none)' | grep 'Candidate:' && echo "UPDATES=YES" || echo "UPDATES=NO"
            ;;
        rhel|centos|rocky|almalinux|ol|fedora)
            sudo yum check-update kernel --quiet 2>/dev/null | grep '^kernel' && echo "UPDATES=YES" || echo "UPDATES=NO"
            ;;
        sles|opensuse*)
            sudo zypper refresh -q 2>/dev/null
            zypper list-updates 2>/dev/null | grep 'kernel-default' && echo "UPDATES=YES" || echo "UPDATES=NO"
            ;;
        *)
            echo "UPDATES=UNKNOWN"
            ;;
    esac
fi
"""


def load_private_key(key_path: str, passphrase: str = None) -> paramiko.PKey:
    """Carga una clave privada SSH."""
    key_path = os.path.expanduser(key_path)
    
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Clave privada no encontrada: {key_path}")
    
    key_classes = [
        paramiko.Ed25519Key,
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.DSSKey,
    ]
    
    for key_class in key_classes:
        try:
            return key_class.from_private_key_file(key_path, password=passphrase)
        except paramiko.PasswordRequiredException:
            if passphrase is None:
                passphrase = getpass.getpass(f"  Passphrase para {key_path}: ")
                try:
                    return key_class.from_private_key_file(key_path, password=passphrase)
                except Exception:
                    continue
        except paramiko.SSHException:
            continue
        except Exception:
            continue
    
    raise ValueError(f"No se pudo cargar la clave {key_path}")


def parse_host_entry(entry: str, default_user: str, default_port: int) -> dict:
    """Parsea una entrada de host."""
    entry = entry.strip()
    user = default_user
    port = default_port
    host = entry
    key_file = None
    
    if "|" in entry:
        entry, key_file = entry.rsplit("|", 1)
        key_file = key_file.strip()
    
    if "@" in entry:
        user, host = entry.rsplit("@", 1)
    
    if ":" in host:
        parts = host.rsplit(":", 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass
    
    return {"host": host, "user": user, "port": port, "key_file": key_file}


def load_hosts_file(filepath: str, default_user: str, default_port: int) -> list:
    """Carga hosts desde un archivo."""
    hosts = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            hosts.append(parse_host_entry(line, default_user, default_port))
    return hosts


def get_host_distro(client: paramiko.SSHClient) -> str:
    """Obtiene la distribución del host remoto."""
    try:
        stdin, stdout, stderr = client.exec_command("cat /etc/os-release", timeout=10)
        output = stdout.read().decode("utf-8", errors="replace")
        
        distro_id = ""
        version_id = ""
        for line in output.splitlines():
            if line.startswith("ID="):
                distro_id = line.split("=", 1)[1].strip('"').lower()
            elif line.startswith("VERSION_ID="):
                version_id = line.split("=", 1)[1].strip('"')
        
        # Mapear
        key_map = {
            "ubuntu": "ubuntu",
            "amzn": "amzn2023" if version_id == "2023" else "amzn2",
            "rhel": "rhel",
            "centos": "centos",
            "rocky": "rocky",
            "almalinux": "alma",
            "ol": "oracle",
            "fedora": "fedora",
            "debian": "debian",
            "sles": "suse",
        }
        
        return key_map.get(distro_id, distro_id)
    
    except Exception:
        return "unknown"


def get_update_command(distro: str) -> str:
    """Obtiene el comando de actualización apropiado."""
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
        return UPDATE_COMMANDS["rhel"]


def update_kernel_ssh(
    host_info: dict,
    global_pkey: paramiko.PKey = None,
    check_only: bool = False,
    timeout: int = 600,
) -> dict:
    """Actualiza kernel en un host via SSH."""
    host = host_info["host"]
    user = host_info["user"]
    port = host_info["port"]
    hostname_display = f"{user}@{host}:{port}"
    
    result = {
        "hostname": hostname_display,
        "success": False,
        "status": "UNKNOWN",
        "message": "",
        "updates_available": False,
        "reboot_required": False,
    }
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Conectar
        connect_kwargs = {
            "hostname": host,
            "port": port,
            "username": user,
            "timeout": 30,
        }
        
        if host_info.get("key_file"):
            connect_kwargs["key_filename"] = os.path.expanduser(host_info["key_file"])
        elif global_pkey:
            connect_kwargs["pkey"] = global_pkey
        else:
            connect_kwargs["allow_agent"] = True
            connect_kwargs["look_for_keys"] = True
        
        client.connect(**connect_kwargs)
        
        # Obtener distribución
        distro = get_host_distro(client)
        result["distro"] = distro
        
        # Seleccionar comando
        if check_only:
            command = CHECK_COMMAND
        else:
            command = get_update_command(distro)
        
        # Ejecutar
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        
        if exit_code == 0:
            result["success"] = True
            result["message"] = output
            
            if "UPDATES=YES" in output or "UPDATES_AVAILABLE=YES" in output:
                result["updates_available"] = True
            
            if "STATUS=NO_UPDATES" in output:
                result["status"] = "NO_UPDATES"
            elif "STATUS=UPDATED_REBOOT_REQUIRED" in output:
                result["status"] = "UPDATED_REBOOT_REQUIRED"
                result["reboot_required"] = True
            elif "UPDATES=YES" in output:
                result["status"] = "UPDATES_AVAILABLE"
            elif "UPDATES=NO" in output:
                result["status"] = "NO_UPDATES"
            else:
                result["status"] = "COMPLETED"
        else:
            result["success"] = False
            result["status"] = "ERROR"
            result["message"] = f"Comando falló (exit {exit_code}): {error[:200]}"
    
    except paramiko.AuthenticationException:
        result["status"] = "ERROR"
        result["message"] = "Error de autenticación SSH"
    except Exception as e:
        result["status"] = "ERROR"
        result["message"] = f"Error: {str(e)[:100]}"
    finally:
        client.close()
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Actualiza kernel en hosts remotos via SSH",
    )
    parser.add_argument("--hosts", type=str, help="Archivo con lista de hosts")
    parser.add_argument("--host", type=str, help="Host individual")
    parser.add_argument("--user", type=str, default="root", help="Usuario SSH")
    parser.add_argument("--port", type=int, default=22, help="Puerto SSH")
    parser.add_argument("--key", type=str, help="Ruta a clave privada SSH")
    parser.add_argument("--passphrase", action="store_true", help="Solicitar passphrase")
    parser.add_argument("--threads", type=int, default=5, help="Hilos paralelos")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout por host")
    parser.add_argument("--check-only", action="store_true", help="Solo verificar, no actualizar")
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    
    args = parser.parse_args()
    
    if not args.hosts and not args.host:
        parser.error("Debes especificar --hosts o --host")
    
    if not args.json:
        print_banner()
        print(colorize("  ACTUALIZACIÓN DE KERNEL - Hosts SSH", "BOLD"))
        if args.check_only:
            print(colorize("  MODO: Solo verificación", "YELLOW"))
        print()
    
    # Construir lista de hosts
    hosts = []
    if args.hosts:
        if not os.path.exists(args.hosts):
            print(colorize(f"ERROR: Archivo no encontrado: {args.hosts}", "RED"))
            sys.exit(1)
        hosts = load_hosts_file(args.hosts, args.user, args.port)
    if args.host:
        hosts.append(parse_host_entry(args.host, args.user, args.port))
    
    if not hosts:
        print("  No se encontraron hosts")
        sys.exit(0)
    
    # Cargar clave
    global_pkey = None
    passphrase = None
    
    if args.passphrase:
        passphrase = getpass.getpass("  Passphrase de la clave privada: ")
    
    if args.key:
        key_path = os.path.expanduser(args.key)
        if not os.path.exists(key_path):
            print(colorize(f"ERROR: Clave no encontrada: {key_path}", "RED"))
            sys.exit(1)
        
        try:
            global_pkey = load_private_key(key_path, passphrase)
            if not args.json:
                print(f"  Clave cargada: {args.key}")
        except Exception as e:
            print(colorize(f"ERROR cargando clave: {e}", "RED"))
            sys.exit(1)
    
    if not args.json:
        print(f"  Hosts a procesar: {len(hosts)}")
        print()
    
    # Procesar en paralelo
    all_results = []
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        for host_info in hosts:
            future = executor.submit(
                update_kernel_ssh,
                host_info,
                global_pkey,
                args.check_only,
                args.timeout,
            )
            futures[future] = host_info
        
        for future in as_completed(futures):
            host_info = futures[future]
            try:
                result = future.result()
                all_results.append(result)
                
                if not args.json:
                    if result["success"]:
                        if result["status"] == "NO_UPDATES":
                            print(f"  ✓ {result['hostname']}: {colorize('No hay actualizaciones', 'GREEN')}")
                        elif result["status"] == "UPDATES_AVAILABLE":
                            print(f"  ⚠ {result['hostname']}: {colorize('Actualizaciones disponibles', 'YELLOW')}")
                        elif result["status"] == "UPDATED_REBOOT_REQUIRED":
                            print(f"  ✓ {result['hostname']}: {colorize('Actualizado - REQUIERE REBOOT', 'YELLOW')}")
                        else:
                            print(f"  ✓ {result['hostname']}: {result['status']}")
                    else:
                        print(colorize(f"  ✗ {result['hostname']}: {result['message'][:60]}", "RED"))
            
            except Exception as e:
                result = {
                    "hostname": f"{host_info['user']}@{host_info['host']}:{host_info['port']}",
                    "success": False,
                    "status": "ERROR",
                    "message": str(e)[:100],
                }
                all_results.append(result)
    
    # Output
    if args.json:
        print(json.dumps(all_results, indent=2, ensure_ascii=False))
    else:
        print()
        print(colorize("=" * 80, "CYAN"))
        print(colorize("  RESUMEN", "BOLD"))
        print(colorize("=" * 80, "CYAN"))
        
        total = len(all_results)
        success = sum(1 for r in all_results if r["success"])
        updates_available = sum(1 for r in all_results if r.get("updates_available", False))
        updated = sum(1 for r in all_results if r.get("status") == "UPDATED_REBOOT_REQUIRED")
        no_updates = sum(1 for r in all_results if r.get("status") == "NO_UPDATES")
        reboot_required = sum(1 for r in all_results if r.get("reboot_required", False))
        
        print(f"\n  Total hosts procesados:      {total}")
        print(colorize(f"  ✓ Procesados exitosamente:   {success}", "GREEN"))
        print(colorize(f"  ⚠ Actualizaciones disponibles: {updates_available}", "YELLOW"))
        print(colorize(f"  ✓ Kernels actualizados:      {updated}", "GREEN"))
        print(f"  ✓ Ya actualizados:           {no_updates}")
        print(colorize(f"  ⚠ Requieren reboot:          {reboot_required}", "YELLOW"))
        
        if reboot_required > 0:
            print()
            print(colorize("  ACCIÓN REQUERIDA:", "BOLD"))
            print("  Los siguientes hosts requieren reboot:")
            for r in all_results:
                if r.get("reboot_required", False):
                    print(f"    - {r['hostname']}")
            print()
            print("  Reinicia manualmente con: ssh user@host 'sudo reboot'")
        
        print()


if __name__ == "__main__":
    main()
