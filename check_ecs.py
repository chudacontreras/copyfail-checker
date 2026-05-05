#!/usr/bin/env python3
"""
check_ecs.py - Verifica instancias de contenedor ECS contra CVE-2026-31431 (Copy Fail)

Verifica las instancias EC2 subyacentes de clusters ECS (tipo EC2, no Fargate).
Fargate es gestionado por AWS y no es verificable directamente.

Requisitos:
  - Python 3.8+
  - boto3 (pip install boto3)
  - Credenciales AWS configuradas
  - SSM Agent en instancias ECS (ECS-optimized AMI lo incluye)

Uso:
  python check_ecs.py --region us-east-1
  python check_ecs.py --cluster mi-cluster --region us-east-1
  python check_ecs.py --all-regions --json
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
    parse_check_output,
    print_banner,
    print_results_table,
    print_summary,
    results_to_json,
    colorize,
)

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("ERROR: boto3 no está instalado. Ejecuta: pip install boto3")
    sys.exit(1)


def get_ecs_clusters(ecs_client) -> list:
    """Lista clusters ECS."""
    arns = []
    paginator = ecs_client.get_paginator("list_clusters")
    for page in paginator.paginate():
        arns.extend(page["clusterArns"])
    return arns


def get_container_instances(ecs_client, cluster_arn: str) -> list:
    """Obtiene instancias de contenedor de un cluster ECS."""
    instance_arns = []
    paginator = ecs_client.get_paginator("list_container_instances")
    for page in paginator.paginate(cluster=cluster_arn):
        instance_arns.extend(page["containerInstanceArns"])

    if not instance_arns:
        return []

    # Obtener detalles (EC2 instance IDs)
    instances = []
    # describe_container_instances acepta max 100
    for i in range(0, len(instance_arns), 100):
        batch = instance_arns[i : i + 100]
        resp = ecs_client.describe_container_instances(
            cluster=cluster_arn, containerInstances=batch
        )
        for ci in resp["containerInstances"]:
            instances.append({
                "container_instance_arn": ci["containerInstanceArn"],
                "ec2_instance_id": ci["ec2InstanceId"],
                "status": ci["status"],
                "agent_connected": ci["agentConnected"],
            })

    return instances


def run_ssm_command(ssm_client, instance_id: str, timeout: int = 60) -> str:
    """Ejecuta verificación vía SSM."""
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
    except (ClientError, Exception):
        pass
    return ""


def check_ssm_online(ssm_client, instance_ids: list) -> dict:
    """Verifica instancias online en SSM."""
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


def main():
    parser = argparse.ArgumentParser(
        description="Verifica instancias ECS (EC2) contra CVE-2026-31431 (Copy Fail)",
    )
    parser.add_argument("--region", type=str, help="Región AWS")
    parser.add_argument("--profile", type=str, help="Perfil AWS")
    parser.add_argument("--cluster", type=str, help="Nombre o ARN del cluster ECS")
    parser.add_argument("--all-regions", action="store_true", help="Todas las regiones")
    parser.add_argument("--json", action="store_true", help="Salida JSON")

    args = parser.parse_args()

    if not args.json:
        print_banner()
        print("  Modo: AWS ECS (instancias de contenedor EC2)")
        print("  NOTA: Fargate es gestionado por AWS y no se verifica aquí.")
        print()

    # Sesión
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
            ecs_client = session.client("ecs", region_name=region)
            ssm_client = session.client("ssm", region_name=region)

            cluster_arns = get_ecs_clusters(ecs_client)

            if args.cluster:
                cluster_arns = [a for a in cluster_arns if args.cluster in a]

            if not cluster_arns:
                continue

            for cluster_arn in cluster_arns:
                cluster_name = cluster_arn.split("/")[-1]
                if not args.json:
                    print(f"  [{region}] Cluster ECS: {cluster_name}")

                container_instances = get_container_instances(ecs_client, cluster_arn)

                if not container_instances:
                    if not args.json:
                        print(f"    Sin instancias EC2 (¿Fargate only?)")
                    continue

                ec2_ids = [ci["ec2_instance_id"] for ci in container_instances]
                ssm_online = check_ssm_online(ssm_client, ec2_ids)

                for ci in container_instances:
                    iid = ci["ec2_instance_id"]
                    hostname = f"{iid} (ECS:{cluster_name})"

                    if ssm_online.get(iid, False):
                        if not args.json:
                            print(f"    Verificando {iid}...")
                        output = run_ssm_command(ssm_client, iid)
                        if output:
                            result = parse_check_output(output, hostname)
                        else:
                            result = VulnerabilityResult(
                                hostname=hostname,
                                status="UNKNOWN",
                                details="SSM comando falló",
                            )
                    else:
                        result = VulnerabilityResult(
                            hostname=hostname,
                            status="PROBABLEMENTE_VULNERABLE",
                            details="SSM no disponible. ECS-optimized AMI (AL2/AL2023) probablemente vulnerable.",
                            recommendations=[
                                "Habilitar SSM en instancias ECS",
                                "Actualizar ECS-optimized AMI cuando haya parche",
                            ],
                        )

                    all_results.append(result)

        except ClientError as e:
            if not args.json:
                print(f"  [{region}] Error: {e}")

    # Output
    if args.json:
        print(json.dumps(results_to_json(all_results), indent=2, ensure_ascii=False))
    else:
        print_results_table(all_results, "Instancias ECS (EC2)")
        print_summary(all_results)

        if all_results:
            print(colorize("  NOTA ECS:", "BOLD"))
            print("  - Contenedores ECS comparten kernel con el host EC2")
            print("  - Un contenedor comprometido puede explotar Copy Fail para escape")
            print("  - Aplicar seccomp profile para bloquear AF_ALG en task definitions")
            print("  - Fargate: AWS gestiona el kernel, contactar soporte AWS para status")
            print()


if __name__ == "__main__":
    main()
