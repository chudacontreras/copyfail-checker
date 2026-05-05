# Scripts de Verificación

[← Volver al README principal](../README.md)

---

## Verificación Local

### `check_local.py`

Verifica el equipo donde se ejecuta el script.

```bash
# Verificación básica
python3 check_local.py

# Salida JSON
python3 check_local.py --json

# Aplicar mitigación automáticamente (requiere sudo)
sudo python3 check_local.py --mitigate
```

---

## Verificación SSH

### `check_ssh.py`

Para servidores remotos accesibles por SSH.

```bash
# Con clave privada (RECOMENDADO)
python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa

# Host individual
python3 check_ssh.py --host 192.168.1.100 --user admin --key ~/.ssh/id_rsa

# Con ssh-agent
ssh-add ~/.ssh/id_rsa
python3 check_ssh.py --hosts hosts.txt

# Clave con passphrase
python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --passphrase

# Paralelismo personalizado
python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --threads 20

# JSON
python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --json > results.json
```

---

## Verificación AWS

### `check_ec2.py`

```bash
# Una región
python3 check_ec2.py --region us-east-1

# Todas las regiones
python3 check_ec2.py --all-regions

# Con perfil AWS
python3 check_ec2.py --all-regions --profile produccion

# Instancias específicas
python3 check_ec2.py --region us-east-1 --instance-ids i-0abc123,i-0def456

# JSON
python3 check_ec2.py --all-regions --json > ec2_results.json
```

### `check_eks.py`

```bash
# Todos los clusters
python3 check_eks.py --region us-east-1

# Cluster específico
python3 check_eks.py --cluster mi-cluster --region us-east-1

# JSON
python3 check_eks.py --all-regions --json > eks_results.json
```

### `check_ecs.py`

```bash
# Todos los clusters
python3 check_ecs.py --region us-east-1

# Cluster específico
python3 check_ecs.py --cluster mi-cluster --region us-east-1

# JSON
python3 check_ecs.py --all-regions --json > ecs_results.json
```

---

## Verificación Unificada

### `check_all.py`

```bash
# AWS + local
python3 check_all.py --region us-east-1

# Todo: AWS + SSH + local
python3 check_all.py --all-regions --ssh-hosts hosts.txt --ssh-key ~/.ssh/id_rsa

# Solo SSH + local
python3 check_all.py --skip-aws --ssh-hosts hosts.txt

# JSON consolidado
python3 check_all.py --all-regions --ssh-hosts hosts.txt --json > reporte.json
```

---

[← Volver al README principal](../README.md) | [Siguiente: Mitigación →](MITIGACION.md)
