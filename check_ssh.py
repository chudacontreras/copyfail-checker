#!/usr/bin/env python3
"""
check_ssh.py - Verifica hosts Linux remotos via SSH contra CVE-2026-31431 (Copy Fail)

Para VPS, servidores en datacenters, máquinas en otras nubes (GCP, Azure, DigitalOcean,
Hetzner, OVH, etc.) o cualquier Linux accesible por SSH.

AUTENTICACIÓN: Usa claves SSH (public/private key) por defecto. NO se exponen passwords.
  - Soporta: RSA, Ed25519, ECDSA, DSA
  - Soporta claves con passphrase (se solicita una sola vez)
  - Soporta ssh-agent
  - Password es opcional y solo como último recurso

Requisitos:
  - Python 3.8+
  - paramiko (pip install paramiko) - para conexión SSH
  - Clave privada SSH (~/.ssh/id_rsa, ~/.ssh/id_ed25519, o especificada con --key)

Uso:
  # Con clave privada (RECOMENDADO - sin passwords)
  python check_ssh.py --hosts hosts.txt --key ~/.ssh/id_ed25519
  python check_ssh.py --host 192.168.1.100 --user admin --key ~/.ssh/mi_clave

  # Con ssh-agent (la clave ya está cargada en el agente)
  python check_ssh.py --hosts hosts.txt

  # Con clave protegida por passphrase
  python check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --passphrase

  # Con clave por host (definida en el archivo de hosts)
  python check_ssh.py --hosts hosts_con_claves.txt

Formato de hosts.txt (un host por línea):
  # Comentarios con #
  # Formato básico:
  192.168.1.100
  mi-servidor.ejemplo.com
  user@10.0.0.5:2222

  # Formato extendido con clave por host (separado por |):
  admin@vps1.ejemplo.com|~/.ssh/id_digitalocean
  deploy@gcp-vm.ejemplo.com:22|~/.ssh/gcp_key
  root@azure-vm.ejemplo.com|/ruta/a/clave_azure
"""

import argparse
import json
import os
import sys
import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.kernel_check import (
    CHECK_COMMANDS,
    VulnerabilityResult,
    parse_check_output,
    print_banner,
    print_results_table,
    print_summary,
    results_to_json,
    colorize,
)

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko no está instalado. Ejecuta: pip install paramiko")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Carga de claves SSH
# ---------------------------------------------------------------------------
def load_private_key(key_path: str, passphrase: str = None) -> paramiko.PKey:
    """
    Carga una clave privada SSH. Soporta RSA, Ed25519, ECDSA, DSA.
    Si la clave tiene passphrase y no se proporcionó, la solicita.
    """
    key_path = os.path.expanduser(key_path)

    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Clave privada no encontrada: {key_path}")

    # Intentar cada tipo de clave
    key_classes = [
        paramiko.Ed25519Key,
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.DSSKey,
    ]

    last_error = None
    for key_class in key_classes:
        try:
            return key_class.from_private_key_file(key_path, password=passphrase)
        except paramiko.PasswordRequiredException:
            # La clave tiene passphrase y no se proporcionó
            if passphrase is None:
                passphrase = getpass.getpass(
                    f"  Passphrase para {key_path}: "
                )
                try:
                    return key_class.from_private_key_file(key_path, password=passphrase)
                except Exception as e:
                    last_error = e
                    continue
        except paramiko.SSHException:
            continue
        except Exception as e:
            last_error = e
            continue

    raise ValueError(
        f"No se pudo cargar la clave {key_path}. "
        f"Verifica que es una clave privada válida (RSA, Ed25519, ECDSA). "
        f"Último error: {last_error}"
    )


def find_default_keys() -> list:
    """Busca claves SSH por defecto en ~/.ssh/"""
    ssh_dir = os.path.expanduser("~/.ssh")
    default_key_names = [
        "id_ed25519",
        "id_rsa",
        "id_ecdsa",
        "id_dsa",
    ]

    found = []
    for name in default_key_names:
        path = os.path.join(ssh_dir, name)
        if os.path.exists(path):
            found.append(path)

    return found


# ---------------------------------------------------------------------------
# Parseo de hosts
# ---------------------------------------------------------------------------
def parse_host_entry(entry: str, default_user: str, default_port: int) -> dict:
    """
    Parsea una entrada de host.
    Formatos soportados:
      host
      user@host
      user@host:port
      user@host:port|/ruta/a/clave
      host|/ruta/a/clave
    """
    entry = entry.strip()
    user = default_user
    port = default_port
    host = entry
    key_file = None

    # Separar clave si está especificada con |
    if "|" in entry:
        entry, key_file = entry.rsplit("|", 1)
        key_file = key_file.strip()

    # Separar usuario
    if "@" in entry:
        user, host = entry.rsplit("@", 1)

    # Separar puerto
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


# ---------------------------------------------------------------------------
# Verificación SSH
# ---------------------------------------------------------------------------
def check_host_ssh(
    host_info: dict,
    global_key_file: str = None,
    global_pkey: paramiko.PKey = None,
    password: str = None,
    passphrase: str = None,
    timeout: int = 30,
) -> VulnerabilityResult:
    """
    Verifica un host via SSH usando autenticación por clave pública.

    Orden de autenticación:
      1. Clave específica del host (definida en hosts.txt con |)
      2. Clave global (--key)
      3. Clave pre-cargada (global_pkey)
      4. ssh-agent
      5. Claves por defecto (~/.ssh/id_ed25519, id_rsa, etc.)
      6. Password (solo si se especificó explícitamente con --password)
    """
    host = host_info["host"]
    user = host_info["user"]
    port = host_info["port"]
    host_key_file = host_info.get("key_file")
    hostname_display = f"{user}@{host}:{port}"

    result = VulnerabilityResult(hostname=hostname_display)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        connect_kwargs = {
            "hostname": host,
            "port": port,
            "username": user,
            "timeout": timeout,
        }

        # Determinar método de autenticación
        if host_key_file:
            # Clave específica para este host
            connect_kwargs["key_filename"] = os.path.expanduser(host_key_file)
            if passphrase:
                connect_kwargs["passphrase"] = passphrase
        elif global_pkey:
            # Clave pre-cargada en memoria
            connect_kwargs["pkey"] = global_pkey
        elif global_key_file:
            # Clave global por ruta
            connect_kwargs["key_filename"] = os.path.expanduser(global_key_file)
            if passphrase:
                connect_kwargs["passphrase"] = passphrase
        elif password:
            # Password como último recurso
            connect_kwargs["password"] = password
        else:
            # Usar ssh-agent + claves por defecto
            connect_kwargs["allow_agent"] = True
            connect_kwargs["look_for_keys"] = True

        client.connect(**connect_kwargs)

        # Ejecutar comandos de verificación
        stdin, stdout, stderr = client.exec_command(CHECK_COMMANDS, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")

        if output:
            result = parse_check_output(output, hostname_display)
        else:
            error = stderr.read().decode("utf-8", errors="replace")
            result.status = "UNKNOWN"
            result.details = f"Comando sin salida. Error: {error[:100]}"

    except paramiko.AuthenticationException:
        result.status = "UNKNOWN"
        result.details = "Error de autenticación SSH. Verifica clave privada o permisos."
    except paramiko.SSHException as e:
        result.status = "UNKNOWN"
        result.details = f"Error SSH: {str(e)[:80]}"
    except FileNotFoundError as e:
        result.status = "UNKNOWN"
        result.details = f"Clave no encontrada: {str(e)[:80]}"
    except OSError as e:
        result.status = "UNKNOWN"
        result.details = f"Error de conexión: {str(e)[:80]}"
    except Exception as e:
        result.status = "UNKNOWN"
        result.details = f"Error: {str(e)[:80]}"
    finally:
        client.close()

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Verifica hosts Linux remotos via SSH contra CVE-2026-31431 (Copy Fail)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
AUTENTICACIÓN (por orden de prioridad):
  1. Clave por host (definida en hosts.txt con separador |)
  2. --key (clave privada global para todos los hosts)
  3. ssh-agent (claves cargadas en el agente del sistema)
  4. Claves por defecto (~/.ssh/id_ed25519, ~/.ssh/id_rsa)
  5. --password (NO recomendado, solo como último recurso)

FORMATO DE ARCHIVO DE HOSTS (un host por línea):
  # Comentarios con #
  192.168.1.100
  admin@vps1.ejemplo.com
  user@10.0.0.5:2222

  # Con clave específica por host (separador |):
  admin@vps-digital.com|~/.ssh/id_digitalocean
  deploy@gcp-vm.com:22|~/.ssh/gcp_key
  root@azure-vm.com|/home/user/.ssh/azure_key

EJEMPLOS:
  # Autenticación por clave (RECOMENDADO)
  python check_ssh.py --hosts hosts.txt --key ~/.ssh/id_ed25519
  python check_ssh.py --host 10.0.0.1 --user admin --key ~/.ssh/mi_clave

  # Con ssh-agent (sin especificar clave)
  ssh-add ~/.ssh/id_ed25519
  python check_ssh.py --hosts hosts.txt

  # Clave con passphrase
  python check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --passphrase
        """,
    )
    parser.add_argument("--hosts", type=str, help="Archivo con lista de hosts")
    parser.add_argument("--host", type=str, help="Host individual a verificar")
    parser.add_argument("--user", type=str, default="root", help="Usuario SSH (default: root)")
    parser.add_argument("--port", type=int, default=22, help="Puerto SSH (default: 22)")
    parser.add_argument(
        "--key", type=str,
        help="Ruta a clave privada SSH (ej: ~/.ssh/id_ed25519, ~/.ssh/id_rsa)"
    )
    parser.add_argument(
        "--passphrase", action="store_true",
        help="Solicitar passphrase para la clave privada (si está protegida)"
    )
    parser.add_argument(
        "--password", action="store_true",
        help="Usar autenticación por contraseña (NO recomendado, usar --key en su lugar)"
    )
    parser.add_argument("--threads", type=int, default=10, help="Hilos paralelos (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout por host en segundos")
    parser.add_argument("--json", action="store_true", help="Salida JSON")

    args = parser.parse_args()

    if not args.hosts and not args.host:
        parser.error("Debes especificar --hosts (archivo) o --host (individual)")

    if not args.json:
        print_banner()
        print("  Modo: SSH remoto (VPS / Datacenters / Otras nubes)")
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
        print("  No se encontraron hosts para verificar.")
        sys.exit(0)

    if not args.json:
        print(f"  Hosts a verificar: {len(hosts)}")
        print(f"  Hilos paralelos:   {args.threads}")

    # Configurar autenticación
    global_pkey = None
    passphrase = None
    password = None

    if args.passphrase:
        passphrase = getpass.getpass("  Passphrase de la clave privada: ")

    if args.key:
        key_path = os.path.expanduser(args.key)
        if not os.path.exists(key_path):
            print(colorize(f"ERROR: Clave privada no encontrada: {key_path}", "RED"))
            sys.exit(1)

        if not args.json:
            print(f"  Autenticación: Clave privada ({args.key})")

        # Pre-cargar la clave para no leerla N veces
        try:
            global_pkey = load_private_key(key_path, passphrase)
            if not args.json:
                key_type = type(global_pkey).__name__.replace("Key", "")
                print(f"  Tipo de clave:  {key_type}")
        except Exception as e:
            print(colorize(f"ERROR cargando clave: {e}", "RED"))
            sys.exit(1)

    elif args.password:
        password = getpass.getpass("  Contraseña SSH: ")
        if not args.json:
            print("  Autenticación: Contraseña (⚠️  considerar usar --key)")
    else:
        # Verificar si hay claves por defecto o ssh-agent
        default_keys = find_default_keys()
        if default_keys:
            if not args.json:
                print(f"  Autenticación: Claves por defecto ({', '.join(os.path.basename(k) for k in default_keys)})")
        else:
            if not args.json:
                print("  Autenticación: ssh-agent (asegúrate de tener claves cargadas)")

    if not args.json:
        print()

    # Verificar hosts en paralelo
    all_results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        for host_info in hosts:
            future = executor.submit(
                check_host_ssh,
                host_info,
                global_key_file=args.key if not global_pkey else None,
                global_pkey=global_pkey,
                password=password,
                passphrase=passphrase,
                timeout=args.timeout,
            )
            futures[future] = host_info

        for future in as_completed(futures):
            host_info = futures[future]
            try:
                result = future.result()
                all_results.append(result)
                if not args.json:
                    status_icon = result.status_emoji
                    print(f"    {status_icon} {result.hostname}: {result.status}")
            except Exception as e:
                result = VulnerabilityResult(
                    hostname=f"{host_info['user']}@{host_info['host']}:{host_info['port']}",
                    status="UNKNOWN",
                    details=f"Error inesperado: {str(e)[:80]}",
                )
                all_results.append(result)

    # Output
    if args.json:
        print(json.dumps(results_to_json(all_results), indent=2, ensure_ascii=False))
    else:
        print_results_table(all_results, "Hosts SSH")
        print_summary(all_results)


if __name__ == "__main__":
    main()
