#!/usr/bin/env python3
"""
check_ec2.py - Verifica instancias EC2 Linux contra CVE-2026-31431 (Copy Fail)

Usa AWS Systems Manager (SSM) para ejecutar verificaciones remotas en instancias EC2.
Para instancias sin SSM, realiza evaluación básica por distribución/AMI.

Requisitos:
  - Python 3.8+
  - boto3 (pip install boto3)
  - Credenciales AWS configuradas
  - SSM Agent activo en instancias (para verificación completa)

Uso:
  python check_ec2.py --region us-east-1
  python check_ec2.py --all-regions --profile produccion
  python check_ec2.py --region eu-west-1 --no-ssm
  python check_ec2.py --all-regions --json > resultados.json
"""

import argparse
import json
import sys
import time
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.kernel_check import (
    CHECK_COMMANDS,
    VulnerabilityResult,
    evaluate_vulnerability,
    is_kernel_vulnerable,
    parse_check_output,
    print_banner,
    print_results_table,
    print_summary,
    results_to_json,
    colorize,
    DISTRO_PATCHES,
)

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("ERROR: boto3 no está instalado. Ejecuta: pip install boto3")
    sys.exit(1)


def get_all_regions(session):
    """Obtiene todas las regiones AWS disponibles."""
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(AllRegions=False)
    return [r["RegionName"] for r in response["Regions"]]


def get_linux_instances(ec2_client, region: str) -> list:
    """Lista instancias EC2 Linux (running/stopped)."""
    instances = []
    paginator = ec2_client.get_paginator("describe_instances")

    filters = [
        {"Name": "instance-state-name", "Values": ["running", "stopped"]},
    ]

    for page in paginator.paginate(Filters=filters):
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                # Saltar Windows
                if inst.get("Platform", "").lower() == "windows":
                    continue

                name = ""
                for tag in inst.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]
                        break

                platform_details = inst.get("PlatformDetails", "Linux/UNIX")
                image_id = inst.get("ImageId", "")

                # Obtener nombre de AMI para mejor detección de distro
                image_name = ""
                try:
                    ami_resp = ec2_client.describe_images(ImageIds=[image_id])
                    if ami_resp["Images"]:
                        image_name = ami_resp["Images"][0].get("Name", "")
                except (ClientError, Exception):
                    pass

                distro = _detect_distro_from_ami(platform_details, image_name)

                instances.append({
                    "instance_id": inst["InstanceId"],
                    "name": name or "(sin nombre)",
                    "state": inst["State"]["Name"],
                    "region": region,
                    "platform_details": platform_details,
                    "image_name": image_name,
                    "distro_guess": distro,
                })

    return instances


def _detect_distro_from_ami(platform_details: str, image_name: str) -> str:
    """Detecta distribución desde metadatos de AMI."""
    combined = (platform_details + " " + image_name).lower()
    if "amazon linux 2023" in combined or "al2023" in combined:
        return "amzn2023"
    elif "amazon linux 2" in combined or "amzn2" in combined:
        return "amzn2"
    elif "ubuntu" in combined:
        if "26.04" in combined:
            return "ubuntu_2604"
        return "ubuntu"
    elif "red hat" in combined or "rhel" in combined:
        return "rhel"
    elif "suse" in combined or "sles" in combined:
        return "suse"
    elif "debian" in combined:
        return "debian"
    elif "centos" in combined:
        return "centos"
    elif "rocky" in combined:
        return "rocky"
    elif "alma" in combined:
        return "alma"
    elif "oracle" in combined:
        return "oracle"
    elif "fedora" in combined:
        return "fedora"
    return "linux"


def check_ssm_managed(ssm_client, instance_ids: list) -> dict:
    """Verifica qué instancias están online en SSM."""
    managed = {}
    if not instance_ids:
        return managed

    try:
        paginator = ssm_client.get_paginator("describe_instance_information")
        for page in paginator.paginate(
            Filters=[{"Key": "InstanceIds", "Values": instance_ids}]
        ):
            for info in page["InstanceInformationList"]:
                managed[info["InstanceId"]] = info.get("PingStatus") == "Online"
    except ClientError:
        pass

    return managed


def run_ssm_command(ssm_client, instance_id: str, timeout: int = 60) -> str:
    """Ejecuta los comandos de verificación vía SSM."""
    try:
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [CHECK_COMMANDS]},
            TimeoutSeconds=timeout,
        )
        command_id = response["Command"]["CommandId"]

        for _ in range(20):
            time.sleep(3)
            try:
                result = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id,
                )
                if result["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
                    return result.get("StandardOutputContent", "")
            except ssm_client.exceptions.InvocationDoesNotExist:
                continue
            except ClientError:
                break

    except (ClientError, Exception) as e:
        return ""

    return ""


def assess_without_ssm(instance: dict) -> VulnerabilityResult:
    """Evaluación básica sin SSM."""
    result = VulnerabilityResult(
        hostname=f"{instance['instance_id']} ({instance['name']})",
        distro=instance["distro_guess"],
    )

    distro_key = instance["distro_guess"]

    if distro_key == "ubuntu_2604":
        result.status = "NO_VULNERABLE"
        result.details = "Ubuntu 26.04+ no está afectado"
    elif distro_key in DISTRO_PATCHES:
        info = DISTRO_PATCHES[distro_key]
        result.status = "PROBABLEMENTE_VULNERABLE"
        note = info.get("note", "") if isinstance(info, dict) else ""
        result.details = f"Distribución {distro_key} probablemente vulnerable. {note} Habilita SSM para verificación exacta."
    else:
        result.status = "PROBABLEMENTE_VULNERABLE"
        result.details = "Distribución Linux probablemente vulnerable. Habilita SSM para verificación exacta."

    result.recommendations = [
        "Habilitar SSM Agent para verificación completa del kernel",
        "Verificar manualmente: uname -r && grep algif_aead /proc/modules",
    ]

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Verifica instancias EC2 Linux contra CVE-2026-31431 (Copy Fail)",
    )
    parser.add_argument("--region", type=str, help="Región AWS (default: región configurada)")
    parser.add_argument("--profile", type=str, help="Perfil AWS")
    parser.add_argument("--all-regions", action="store_true", help="Verificar todas las regiones")
    parser.add_argument("--no-ssm", action="store_true", help="No usar SSM (evaluación básica)")
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    parser.add_argument("--instance-ids", type=str, help="IDs específicos separados por coma")

    args = parser.parse_args()

    if not args.json:
        print_banner()
        print("  Modo: AWS EC2 (via SSM)")
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
        print("  Configura con: aws configure")
        sys.exit(1)
    except ClientError as e:
        print(colorize(f"ERROR: {e}", "RED"))
        sys.exit(1)

    # Regiones
    if args.all_regions:
        regions = get_all_regions(session)
        if not args.json:
            print(f"  Verificando {len(regions)} regiones...")
    else:
        regions = [session.region_name or "us-east-1"]
        if not args.json:
            print(f"  Región: {regions[0]}")

    if not args.json:
        print()

    # Recopilar y verificar
    all_results = []

    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)
            instances = get_linux_instances(ec2_client, region)

            # Filtrar por IDs si se especificaron
            if args.instance_ids:
                target_ids = [i.strip() for i in args.instance_ids.split(",")]
                instances = [i for i in instances if i["instance_id"] in target_ids]

            if not instances:
                continue

            if not args.json:
                print(f"  [{region}] {len(instances)} instancias Linux encontradas")

            if args.no_ssm:
                for inst in instances:
                    result = assess_without_ssm(inst)
                    all_results.append(result)
            else:
                ssm_client = session.client("ssm", region_name=region)
                running_ids = [i["instance_id"] for i in instances if i["state"] == "running"]
                ssm_managed = check_ssm_managed(ssm_client, running_ids)

                for inst in instances:
                    if inst["state"] != "running":
                        result = VulnerabilityResult(
                            hostname=f"{inst['instance_id']} ({inst['name']})",
                            distro=inst["distro_guess"],
                            status="UNKNOWN",
                            details="Instancia detenida - no se puede verificar",
                        )
                        all_results.append(result)
                        continue

                    iid = inst["instance_id"]
                    if ssm_managed.get(iid, False):
                        if not args.json:
                            print(f"    Verificando {iid} ({inst['name']})...")
                        output = run_ssm_command(ssm_client, iid)
                        if output:
                            result = parse_check_output(output, f"{iid} ({inst['name']})")
                        else:
                            result = assess_without_ssm(inst)
                            result.details += " (SSM comando falló)"
                    else:
                        result = assess_without_ssm(inst)
                        result.details += " (SSM no disponible)"

                    all_results.append(result)

        except ClientError as e:
            if not args.json:
                print(f"  [{region}] Error: {e}")

    # Output
    if args.json:
        print(json.dumps(results_to_json(all_results), indent=2, ensure_ascii=False))
    else:
        print_results_table(all_results, "Instancias EC2")
        print_summary(all_results)


if __name__ == "__main__":
    main()
