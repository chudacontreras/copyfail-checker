#!/usr/bin/env python3
"""
monitor_updates.py - Monitor periódico de actualizaciones de kernel

Verifica periódicamente si hay actualizaciones de kernel disponibles
y notifica cuando estén listas para instalar.

Útil para ejecutar en cron y recibir alertas cuando el parche esté disponible.

Requisitos:
  - Python 3.8+
  - boto3, paramiko (pip install boto3 paramiko)

Uso:
  python monitor_updates.py --region us-east-1 --hosts hosts.txt --key ~/.ssh/id_rsa
  python monitor_updates.py --region us-east-1 --hosts hosts.txt --key ~/.ssh/id_rsa --notify-email admin@example.com
  
Cron (verificar diariamente a las 9 AM):
  0 9 * * * cd /path/to/copyfail-checker && python3 monitor_updates.py --region us-east-1 --hosts hosts.txt --key ~/.ssh/id_rsa >> /var/log/copyfail-monitor.log 2>&1
"""

import argparse
import json
import os
import sys
import subprocess
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.kernel_check import colorize, print_banner


def check_ec2_updates(region: str, profile: str = None) -> dict:
    """Verifica actualizaciones en EC2."""
    cmd = [sys.executable, "update_kernel_ec2.py", "--region", region, "--check-only", "--json"]
    if profile:
        cmd.extend(["--profile", profile])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            return {
                "success": True,
                "total": len(data),
                "updates_available": sum(1 for r in data if r.get("updates_available", False)),
                "results": data,
            }
    except Exception as e:
        return {"success": False, "error": str(e)}
    
    return {"success": False, "error": "No data"}


def check_ssh_updates(hosts_file: str, key_file: str) -> dict:
    """Verifica actualizaciones en hosts SSH."""
    cmd = [
        sys.executable, "update_kernel_ssh.py",
        "--hosts", hosts_file,
        "--key", key_file,
        "--check-only",
        "--json"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            return {
                "success": True,
                "total": len(data),
                "updates_available": sum(1 for r in data if r.get("updates_available", False)),
                "results": data,
            }
    except Exception as e:
        return {"success": False, "error": str(e)}
    
    return {"success": False, "error": "No data"}


def send_notification(message: str, email: str = None, webhook: str = None):
    """Envía notificación (email o webhook)."""
    if email:
        # Usar sendmail o mail command
        try:
            subprocess.run(
                ["mail", "-s", "CVE-2026-31431: Actualizaciones Disponibles", email],
                input=message.encode(),
                timeout=30,
            )
            print(f"  ✓ Notificación enviada a {email}")
        except Exception as e:
            print(f"  ✗ Error enviando email: {e}")
    
    if webhook:
        # Webhook genérico (Slack, Discord, etc.)
        try:
            import urllib.request
            import urllib.parse
            
            payload = json.dumps({"text": message}).encode()
            req = urllib.request.Request(
                webhook,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10)
            print(f"  ✓ Notificación enviada a webhook")
        except Exception as e:
            print(f"  ✗ Error enviando webhook: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor periódico de actualizaciones de kernel para CVE-2026-31431",
    )
    parser.add_argument("--region", type=str, help="Región AWS")
    parser.add_argument("--profile", type=str, help="Perfil AWS")
    parser.add_argument("--hosts", type=str, help="Archivo de hosts SSH")
    parser.add_argument("--key", type=str, help="Clave SSH")
    parser.add_argument("--notify-email", type=str, help="Email para notificaciones")
    parser.add_argument("--notify-webhook", type=str, help="Webhook URL para notificaciones")
    parser.add_argument("--quiet", action="store_true", help="Solo mostrar si hay actualizaciones")
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    
    args = parser.parse_args()
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if not args.json and not args.quiet:
        print_banner()
        print(colorize(f"  MONITOR DE ACTUALIZACIONES - {timestamp}", "BOLD"))
        print()
    
    results = {
        "timestamp": timestamp,
        "ec2": None,
        "ssh": None,
        "updates_available": False,
    }
    
    # Verificar EC2
    if args.region:
        if not args.quiet:
            print(f"  Verificando instancias EC2 en {args.region}...")
        
        ec2_result = check_ec2_updates(args.region, args.profile)
        results["ec2"] = ec2_result
        
        if ec2_result.get("success") and ec2_result.get("updates_available", 0) > 0:
            results["updates_available"] = True
            if not args.quiet:
                print(colorize(f"    ⚠ {ec2_result['updates_available']} instancias con actualizaciones disponibles", "YELLOW"))
        elif not args.quiet:
            print(f"    ✓ No hay actualizaciones disponibles")
    
    # Verificar SSH
    if args.hosts and args.key:
        if not args.quiet:
            print(f"  Verificando hosts SSH...")
        
        ssh_result = check_ssh_updates(args.hosts, args.key)
        results["ssh"] = ssh_result
        
        if ssh_result.get("success") and ssh_result.get("updates_available", 0) > 0:
            results["updates_available"] = True
            if not args.quiet:
                print(colorize(f"    ⚠ {ssh_result['updates_available']} hosts con actualizaciones disponibles", "YELLOW"))
        elif not args.quiet:
            print(f"    ✓ No hay actualizaciones disponibles")
    
    # Output
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    elif not args.quiet:
        print()
        print(colorize("=" * 80, "CYAN"))
        print(colorize("  RESUMEN", "BOLD"))
        print(colorize("=" * 80, "CYAN"))
        print()
        
        if results["updates_available"]:
            print(colorize("  ⚠ ACTUALIZACIONES DISPONIBLES", "YELLOW"))
            print()
            print("  Parches de kernel están disponibles para instalar.")
            print("  Ejecuta los siguientes comandos para actualizar:")
            print()
            
            if results["ec2"] and results["ec2"].get("updates_available", 0) > 0:
                print(colorize("  EC2:", "BOLD"))
                print(f"    python3 update_kernel_ec2.py --region {args.region}")
                print()
            
            if results["ssh"] and results["ssh"].get("updates_available", 0) > 0:
                print(colorize("  SSH:", "BOLD"))
                print(f"    python3 update_kernel_ssh.py --hosts {args.hosts} --key {args.key}")
                print()
        else:
            print(colorize("  ✓ No hay actualizaciones disponibles", "GREEN"))
            print()
            print("  Los parches de kernel aún no están disponibles.")
            print("  Este script continuará monitoreando.")
        
        print()
    
    # Notificar si hay actualizaciones
    if results["updates_available"]:
        message = f"""CVE-2026-31431 (Copy Fail) - Actualizaciones Disponibles

Timestamp: {timestamp}

"""
        
        if results["ec2"] and results["ec2"].get("updates_available", 0) > 0:
            message += f"EC2: {results['ec2']['updates_available']} instancias con actualizaciones\n"
        
        if results["ssh"] and results["ssh"].get("updates_available", 0) > 0:
            message += f"SSH: {results['ssh']['updates_available']} hosts con actualizaciones\n"
        
        message += f"""
Acción requerida:
- Revisar actualizaciones disponibles
- Aplicar parches de kernel
- Reiniciar sistemas

Comandos:
"""
        
        if args.region:
            message += f"  python3 update_kernel_ec2.py --region {args.region}\n"
        if args.hosts and args.key:
            message += f"  python3 update_kernel_ssh.py --hosts {args.hosts} --key {args.key}\n"
        
        if args.notify_email or args.notify_webhook:
            if not args.quiet:
                print("  Enviando notificaciones...")
            send_notification(message, args.notify_email, args.notify_webhook)
    
    # Exit code: 0 si no hay actualizaciones, 1 si hay actualizaciones (útil para scripts)
    sys.exit(1 if results["updates_available"] else 0)


if __name__ == "__main__":
    main()
