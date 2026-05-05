#!/usr/bin/env python3
"""
check_eks.py - Verifica nodos EKS contra CVE-2026-31431 (Copy Fail)

Verifica los nodos worker de clusters EKS usando SSM (los nodos EKS managed
tienen SSM Agent por defecto) o kubectl si está disponible.

Requisitos:
  - Python 3.8+
  - boto3 (pip install boto3)
  - Credenciales AWS configuradas
  - Nodos EKS con SSM Agent (managed node groups lo tienen por defecto)

Uso:
  python check_eks.py --region us-east-1
  python check_eks.py --cluster mi-cluster --region us-east-1
  python check_eks.py --all-regions --json
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


def get_eks_clusters(eks_client) -> list:
    """Lista clusters EKS en la región."""
    clusters = []
    paginator = eks_client.get_paginator("list_clusters")
    for page in paginator.paginate():
        clusters.extend(page["clusters"])
    return clusters


def get_eks_nodegroups(eks_client, cluster_name: str) -> list:
    """Lista node groups de un cluster."""
    nodegroups = []
    paginator = eks_client.get_paginator("list_nodegroups")
    for page in paginator.paginate(clusterName=cluster_name):
        nodegroups.extend(page["nodegroups"])
    return nodegroups


def get_nodegroup_instances(eks_client, ec2_client, cluster_name: str, nodegroup_name: str) -> list:
    """Obtiene instancias EC2 de un node group."""
    try:
        ng = eks_client.describe_nodegroup(
            clusterName=cluster_name,
            nodegroupName=nodegroup_name,
        )["nodegroup"]

        # Obtener ASG
        asg_names = []
        for resource in ng.get("resources", {}).get("autoScalingGroups", []):
            asg_names.append(resource["name"])

        if not asg_names:
            return []

        # Obtener instancias del ASG
        asg_client = eks_client._session.create_client(
            "autoscaling", region_name=eks_client.meta.region_name
        )

        instance_ids = []
        try:
            # Usar boto3 session directamente
            session = boto3.Session(region_name=eks_client.meta.region_name)
            asg_client = session.client("autoscaling")
            resp = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=asg_names)
            for asg in resp["AutoScalingGroups"]:
                for inst in asg["Instances"]:
                    if inst["LifecycleState"] == "InService":
                        instance_ids.append(inst["InstanceId"])
        except (ClientError, Exception):
            pass

        return instance_ids

    except (ClientError, Exception):
        return []


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


def main():
    parser = argparse.ArgumentParser(
        description="Verifica nodos EKS contra CVE-2026-31431 (Copy Fail)",
    )
    parser.add_argument("--region", type=str, help="Región AWS")
    parser.add_argument("--profile", type=str, help="Perfil AWS")
    parser.add_argument("--cluster", type=str, help="Nombre del cluster EKS específico")
    parser.add_argument("--all-regions", action="store_true", help="Todas las regiones")
    parser.add_argument("--json", action="store_true", help="Salida JSON")

    args = parser.parse_args()

    if not args.json:
        print_banner()
        print("  Modo: AWS EKS (nodos worker via SSM)")
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

    if not args.json:
        print(f"  Regiones: {', '.join(regions)}")
        print()

    all_results = []

    for region in regions:
        try:
            eks_client = session.client("eks", region_name=region)
            ssm_client = session.client("ssm", region_name=region)
            ec2_client = session.client("ec2", region_name=region)

            clusters = get_eks_clusters(eks_client)
            if args.cluster:
                clusters = [c for c in clusters if c == args.cluster]

            if not clusters:
                continue

            for cluster_name in clusters:
                if not args.json:
                    print(f"  [{region}] Cluster: {cluster_name}")

                nodegroups = get_eks_nodegroups(eks_client, cluster_name)

                for ng_name in nodegroups:
                    instance_ids = get_nodegroup_instances(eks_client, ec2_client, cluster_name, ng_name)

                    if not instance_ids:
                        if not args.json:
                            print(f"    NodeGroup {ng_name}: sin instancias activas")
                        continue

                    if not args.json:
                        print(f"    NodeGroup {ng_name}: {len(instance_ids)} nodos")

                    ssm_online = check_ssm_online(ssm_client, instance_ids)

                    for iid in instance_ids:
                        hostname = f"{iid} (EKS:{cluster_name}/{ng_name})"

                        if ssm_online.get(iid, False):
                            if not args.json:
                                print(f"      Verificando {iid}...")
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
                                details="SSM no disponible. Nodos EKS con AL2/AL2023 son probablemente vulnerables.",
                                recommendations=[
                                    "Habilitar SSM en el node group",
                                    "Aplicar mitigación via DaemonSet o user-data del launch template",
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
        print_results_table(all_results, "Nodos EKS")
        print_summary(all_results)

        if all_results:
            print(colorize("  NOTA EKS:", "BOLD"))
            print("  - Los nodos EKS comparten kernel con contenedores (riesgo de escape)")
            print("  - Aplicar seccomp para bloquear AF_ALG en pods no confiables")
            print("  - Considerar actualizar AMI del node group cuando haya parche")
            print()


if __name__ == "__main__":
    main()
