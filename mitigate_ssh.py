#!/usr/bin/env python3
"""
mitigate_ssh.py - Aplica mitigación automática a hosts remotos via SSH

Aplica la mitigación apropiada según el tipo de distribución:
  - Distros con módulo cargable: modprobe blacklist
  - Distros EL (kernel built-in): initcall_blacklist boot param

Requisitos:
  - Python 3.8+
  - paramiko (pip install paramiko)
  - Acceso SSH con clave privada a los hosts

Uso:
  python mitigate_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa
  python mitigate_ssh.py --host 192.168.1.100 --user admin --key ~/.ssh/mi_clave
  python mitigate_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --dry-run
  python mitigate_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --json > results.json
"""

import argparse
import json
import os
import sys
import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.kernel_check import (
    is_el_distro,
    colorize,
    print_banner,
)

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko no está instalado. Ejecuta: pip install paramiko")
    sys.exit(1)


# Comandos de mitigación (mismos que en mitigate_ec2.py)
MITIGATION_MODULE = """
#!/bin/bash
set -e

echo "=== Aplicando mitigación modprobe para CVE-2026-31431 ==="

# Crear archivo de configuración modprobe
echo "# CVE-2026-31431 (Copy Fail) mitigation" | sudo tee /etc/modprobe.d/disable-algif-aead-cve-2026-31431.conf
echo "install algif_aead /bin/false" | sudo tee -a /etc/modprobe.d/disable-algif-aead-cve-2026-31431.conf

echo "✓ Archivo modprobe creado"

# Intentar descargar el módulo si está cargado
if lsmod | grep -q '^algif_aead '; then
    echo "Módulo algif_aead está cargado, intentando descargarlo..."
    sudo rmmod algif_aead 2>/dev/null && echo "✓ Módulo descargado" || echo "⚠ No se pudo descargar (puede estar en uso, requiere reboot)"
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
sudo grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"

echo "✓ Boot parameter agregado"
echo "STATUS=MITIGATED_REBOOT_REQUIRED"
echo "⚠ REQUIERE REBOOT para activar mitigación"

# Verificar que se aplicó
if sudo grubby --info=ALL | grep -q 'initcall_blacklist=algif_aead_init'; then
    echo "✓ Verificación: boot param presente en configuración GRUB"
else
    echo "⚠ Advertencia: no se pudo verificar en configuración GRUB"
fi

echo "=== Mitigación completada - REBOOT REQUERIDO ==="
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
        for line in output.splitlines():
            if line.startswith("ID="):
                distro_id = line.split("=", 1)[1].strip('"').lower()
                break
        
        # Mapear a claves conocidas
        key_map = {
            "ubuntu": "ubuntu",
            "amzn": "amzn2023",
            "rhel": "rhel",
            "centos": "centos",
            "rocky": "rocky",
            "almalinux": "alma",
            "ol": "oracle",
            "oracle": "oracle",
            "fedora": "fedora",
            "debian": "debian",
            "sles": "suse",
        }
        
        return key_map.get(distro_id, distro_id)
    
    except Exception:
        return "unknown"


def apply_mitigation_ssh(
    host_info: dict,
    global_pkey: paramiko.PKey = None,
    dry_run: bool = False,
    timeout: int = 60,
) -> dict:
    """Aplica mitigación via SSH a un host."""
    host = host_info["host"]
    user = host_info["user"]
    port = host_info["port"]
    hostname_display = f"{user}@{host}:{port}"
    
    result = {
        "hostname": hostname_display,
        "success": False,
        "status": "UNKNOWN",
        "message": "",
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
            "timeout": timeout,
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
        
        if dry_run:
            result["success"] = True
            result["status"] = "DRY_RUN"
            result["message"] = f"[DRY RUN] Se aplicaría mitigación {'EL' if is_el_distro(distro) else 'modprobe'}"
            return result
        
        # Seleccionar comando
        if is_el_distro(distro):
            command = MITIGATION_EL
        else:
            command = MITIGATION_MODULE
        
        # Ejecutar
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        
        if exit_code == 0:
            result["success"] = True
            result["message"] = output
            
            if "MITIGATED_REBOOT_REQUIRED" in output:
                result["status"] = "MITIGATED_REBOOT_REQUIRED"
                result["reboot_required"] = True
            elif "MITIGATED_ACTIVE" in output:
                result["status"] = "MITIGATED_ACTIVE"
            elif "ALREADY_MITIGATED" in output:
                result["status"] = "ALREADY_MITIGATED"
            else:
                result["status"] = "MITIGATED"
                result["reboot_required"] = True
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
        description="Aplica mitigación automática a hosts remotos via SSH",
    )
    parser.add_argument("--hosts", type=str, help="Archivo con lista de hosts")
    parser.add_argument("--host", type=str, help="Host individual")
    parser.add_argument("--user", type=str, default="root", help="Usuario SSH (default: root)")
    parser.add_argument("--port", type=int, default=22, help="Puerto SSH (default: 22)")
    parser.add_argument("--key", type=str, help="Ruta a clave privada SSH")
    parser.add_argument("--passphrase", action="store_true", help="Solicitar passphrase")
    parser.add_argument("--threads", type=int, default=10, help="Hilos paralelos")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout por host")
    parser.add_argument("--dry-run", action="store_true", help="Simular sin aplicar cambios")
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    
    args = parser.parse_args()
    
    if not args.hosts and not args.host:
        parser.error("Debes especificar --hosts o --host")
    
    if not args.json:
        print_banner()
        print(colorize("  APLICACIÓN DE MITIGACIÓN - Hosts SSH", "BOLD"))
        if args.dry_run:
            print(colorize("  MODO: DRY RUN (simulación)", "YELLOW"))
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
    
    # Aplicar mitigación en paralelo
    all_results = []
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        for host_info in hosts:
            future = executor.submit(
                apply_mitigation_ssh,
                host_info,
                global_pkey,
                args.dry_run,
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
                        status_color = "GREEN" if result["status"] == "MITIGATED_ACTIVE" else "YELLOW"
                        print(f"  ✓ {result['hostname']}: {colorize(result['status'], status_color)}")
                        if result["reboot_required"]:
                            print(colorize(f"    ⚠ REQUIERE REBOOT", "YELLOW"))
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
        reboot_required = sum(1 for r in all_results if r.get("reboot_required", False))
        
        print(f"\n  Total hosts procesados:  {total}")
        print(colorize(f"  ✓ Mitigación exitosa:    {success}", "GREEN"))
        print(colorize(f"  ✗ Errores:               {total - success}", "RED"))
        print(colorize(f"  ⚠ Requieren reboot:      {reboot_required}", "YELLOW"))
        
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
