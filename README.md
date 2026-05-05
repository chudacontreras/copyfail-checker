# CVE-2026-31431 "Copy Fail" - Suite de Verificación de Vulnerabilidad

Suite de scripts Python para verificar si tus sistemas Linux son vulnerables a **CVE-2026-31431 (Copy Fail)**, una vulnerabilidad de escalación de privilegios local en el kernel Linux.

## Sobre la Vulnerabilidad

| Campo | Detalle |
|-------|---------|
| **CVE** | CVE-2026-31431 |
| **Nombre** | Copy Fail |
| **CVSS** | 7.8 (HIGH) |
| **Tipo** | Local Privilege Escalation (LPE) |
| **Componente** | `algif_aead` - módulo AEAD del crypto API del kernel (AF_ALG) |
| **Introducida** | Julio 2017 (commit `72548b093ee3`) |
| **Kernels vulnerables** | 4.14 hasta 6.18.21, 6.19.11, y anteriores a 7.0 |
| **Kernels parcheados** | 7.0+, 6.19.12+, 6.18.22+ |
| **Exploit público** | Sí (~732 bytes Python, funciona sin race conditions) |
| **CISA KEV** | Añadido (explotación activa confirmada) |

### ¿Cómo funciona?

Un usuario local sin privilegios puede corromper el page cache de binarios setuid (como `/usr/bin/su`) usando operaciones `splice()` + `AF_ALG` socket, obteniendo root en segundos. A diferencia de Dirty Pipe o Dirty COW, no requiere race conditions y funciona con 100% de fiabilidad.

### Distribuciones afectadas

| Distribución | Estado del parche (al 4 mayo 2026) |
|---|---|
| **Ubuntu 20.04–24.04** | Mitigación kmod disponible. Kernel fix pendiente |
| **Ubuntu 26.04 (Resolute)** | NO afectado |
| **Amazon Linux 2** | Parche pendiente |
| **Amazon Linux 2023** | Parche pendiente |
| **RHEL 8/9/10** | Clasificado Important. Fix en progreso |
| **SUSE (todas)** | Parches publicados 3 mayo 2026 |
| **Rocky Linux 9 LTS** | Parches CIQ disponibles |
| **AlmaLinux** | Parches en producción desde 1 mayo 2026 |
| **Debian** | Afectado, verificar tracker |
| **openSUSE Tumbleweed** | Parcheado (kernel 6.19.12) |
| **openSUSE Slowroll** | Parcheado (kernel 6.18.22) |

### Nota importante sobre EL distros (RHEL/Rocky/CentOS/Oracle)

En estas distribuciones, `algif_aead` está compilado directamente en el kernel (`CONFIG_CRYPTO_USER_API_AEAD=y`), **no como módulo**. Esto significa que `rmmod` y `/etc/modprobe.d/` **no funcionan**. La mitigación correcta es via boot parameter:

```bash
sudo grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"
sudo reboot
```

---

## Estructura del Proyecto

```
copyfail-checker/
├── README.md              # Este archivo
├── requirements.txt       # Dependencias Python
├── check_local.py         # Verificación del equipo local
├── check_ec2.py           # Instancias EC2 via SSM
├── check_eks.py           # Nodos EKS via SSM
├── check_ecs.py           # Instancias ECS (EC2) via SSM
├── check_ssh.py           # Hosts remotos via SSH (VPS, datacenters, otras nubes)
├── check_all.py           # Script unificado (ejecuta todos)
└── lib/
    ├── __init__.py
    └── kernel_check.py    # Lógica central compartida
```

---

## Requisitos

### Python
- Python 3.8 o superior

### Dependencias
```bash
pip install -r requirements.txt
```

O instalar manualmente:
```bash
# Para scripts AWS (EC2, EKS, ECS)
pip install boto3

# Para script SSH (VPS, datacenters, otras nubes)
pip install paramiko
```

### Credenciales AWS (solo para scripts AWS)
```bash
# Opción 1: AWS CLI configurado
aws configure

# Opción 2: Variables de entorno
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1

# Opción 3: Perfil nombrado
aws configure --profile produccion
# Luego usar: --profile produccion
```

### SSM Agent (para verificación completa en EC2/EKS/ECS)
Las instancias deben tener:
1. SSM Agent instalado y activo (viene por defecto en AMIs de Amazon Linux, Ubuntu en AWS)
2. Rol IAM con política `AmazonSSMManagedInstanceCore`

Sin SSM, los scripts hacen evaluación básica por distribución/AMI.

---

## Uso por Script

### 1. `check_local.py` - Equipo Local

Verifica la máquina donde se ejecuta el script. Ideal para tu estación de trabajo Linux, WSL, o un servidor con acceso directo.

```bash
# Verificación básica
python check_local.py

# Salida JSON
python check_local.py --json

# Aplicar mitigación automáticamente (requiere sudo)
sudo python check_local.py --mitigate
```

**Desde Windows (WSL):**
```powershell
wsl python3 check_local.py
```

**Desde macOS:** macOS no usa kernel Linux, no es vulnerable.

---

### 2. `check_ec2.py` - Instancias EC2

Verifica todas las instancias EC2 Linux en tu cuenta AWS.

```bash
# Una región
python check_ec2.py --region us-east-1

# Todas las regiones
python check_ec2.py --all-regions

# Con perfil AWS específico
python check_ec2.py --all-regions --profile produccion

# Instancias específicas
python check_ec2.py --region us-east-1 --instance-ids i-0abc123,i-0def456

# Sin SSM (evaluación básica por AMI)
python check_ec2.py --region us-east-1 --no-ssm

# JSON para integración
python check_ec2.py --all-regions --json > ec2_results.json
```

**Permisos IAM necesarios:**
```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:DescribeInstances",
    "ec2:DescribeImages",
    "ec2:DescribeRegions",
    "ssm:DescribeInstanceInformation",
    "ssm:SendCommand",
    "ssm:GetCommandInvocation"
  ],
  "Resource": "*"
}
```

---

### 3. `check_eks.py` - Nodos EKS

Verifica los nodos worker de clusters EKS. Los managed node groups tienen SSM Agent por defecto.

```bash
# Todos los clusters en una región
python check_eks.py --region us-east-1

# Cluster específico
python check_eks.py --cluster mi-cluster --region us-east-1

# Todas las regiones
python check_eks.py --all-regions --profile produccion

# JSON
python check_eks.py --all-regions --json > eks_results.json
```

**Permisos IAM adicionales:**
```json
{
  "Effect": "Allow",
  "Action": [
    "eks:ListClusters",
    "eks:DescribeNodegroup",
    "eks:ListNodegroups",
    "autoscaling:DescribeAutoScalingGroups"
  ],
  "Resource": "*"
}
```

**Nota sobre EKS:**
- Los nodos EKS comparten kernel con todos los pods
- Un pod comprometido puede explotar Copy Fail para escape de contenedor
- Aplicar seccomp profiles para bloquear AF_ALG en pods no confiables
- Considerar actualizar la AMI del node group cuando haya parche

---

### 4. `check_ecs.py` - Instancias ECS

Verifica las instancias EC2 subyacentes de clusters ECS (tipo EC2 launch type).

```bash
# Todos los clusters en una región
python check_ecs.py --region us-east-1

# Cluster específico
python check_ecs.py --cluster mi-cluster --region us-east-1

# JSON
python check_ecs.py --all-regions --json > ecs_results.json
```

**Nota sobre Fargate:** Fargate es gestionado por AWS. El kernel no es accesible directamente. Contactar soporte AWS para status de parche en Fargate.

**Permisos IAM adicionales:**
```json
{
  "Effect": "Allow",
  "Action": [
    "ecs:ListClusters",
    "ecs:ListContainerInstances",
    "ecs:DescribeContainerInstances"
  ],
  "Resource": "*"
}
```

---

### 5. `check_ssh.py` - Hosts Remotos (VPS / Datacenters / Otras Nubes)

Para cualquier servidor Linux accesible por SSH: VPS (DigitalOcean, Hetzner, OVH, Linode), servidores en datacenters on-premise, instancias en GCP, Azure, etc.

**🔐 Usa autenticación por clave pública (public/private key) por defecto. No se exponen passwords.**

```bash
# Con clave privada (RECOMENDADO)
python check_ssh.py --hosts hosts.txt --key ~/.ssh/id_ed25519
python check_ssh.py --host 192.168.1.100 --user admin --key ~/.ssh/id_rsa

# Con ssh-agent (claves ya cargadas)
ssh-add ~/.ssh/id_ed25519
python check_ssh.py --hosts hosts.txt

# Clave con passphrase (se solicita una sola vez de forma segura)
python check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --passphrase

# Clave diferente por host (definida en el archivo)
python check_ssh.py --hosts hosts_con_claves.txt

# Paralelismo personalizado
python check_ssh.py --hosts hosts.txt --key ~/.ssh/id_ed25519 --threads 20

# JSON
python check_ssh.py --hosts hosts.txt --key ~/.ssh/id_ed25519 --json > ssh_results.json
```

**Formato del archivo `hosts.txt`:**
```
# Comentarios con #
# Formato básico: [usuario@]host[:puerto]

# Servidores con usuario por defecto (--user)
192.168.1.100
mi-servidor.ejemplo.com

# Con usuario específico
admin@vps1.digitalocean.com
ubuntu@10.0.0.5

# Con puerto personalizado
root@servidor.ejemplo.com:2222
deploy@bastion.empresa.com:2200

# FORMATO EXTENDIDO: Con clave privada por host (separador |)
# Útil cuando cada servidor tiene su propia clave
admin@vps-digital.com|~/.ssh/id_digitalocean
deploy@gcp-instance.com:22|~/.ssh/gcp_key
root@azure-vm.empresa.com|~/.ssh/azure_key
ubuntu@hetzner-vps.com|/home/user/.ssh/hetzner_ed25519
```

**Autenticación SSH (por orden de prioridad, sin passwords):**
1. **Clave por host** - Definida en `hosts.txt` con separador `|` (cada servidor su propia clave)
2. **`--key`** - Clave privada global para todos los hosts
3. **ssh-agent** - Claves cargadas en el agente del sistema
4. **Claves por defecto** - `~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, `~/.ssh/id_ecdsa`
5. `--password` - Solo como último recurso (NO recomendado)

**Tipos de clave soportados:** RSA, Ed25519, ECDSA, DSA

**Claves con passphrase:** Usa `--passphrase` y se solicita una sola vez de forma segura (no queda en historial ni logs)

---

### 6. `check_all.py` - Verificación Unificada

Ejecuta todos los scripts y genera un reporte consolidado.

```bash
# AWS + local
python check_all.py --region us-east-1

# Todo: AWS (todas las regiones) + SSH + local
python check_all.py --all-regions --profile prod --ssh-hosts hosts.txt --ssh-key ~/.ssh/id_rsa

# Solo SSH + local (sin AWS)
python check_all.py --skip-aws --ssh-hosts hosts.txt

# Solo AWS (sin local)
python check_all.py --skip-local --all-regions

# JSON consolidado
python check_all.py --all-regions --ssh-hosts hosts.txt --json > reporte_completo.json
```

---

## Interpretación de Resultados

| Estado | Significado |
|--------|-------------|
| 🔴 **VULNERABLE** | Kernel en rango vulnerable, sin mitigación. **Acción inmediata requerida.** |
| 🟠 **PROBABLEMENTE VULNERABLE** | No se pudo verificar kernel exacto, pero la distribución está afectada. |
| 🟡 **MITIGADO** | Kernel vulnerable pero mitigación aplicada (modprobe o boot param). |
| 🟢 **NO VULNERABLE** | Kernel parcheado o fuera del rango vulnerable. |
| ⚪ **DESCONOCIDO** | No se pudo conectar o verificar. |

---

## Mitigación

### Para distribuciones con módulo cargable (Ubuntu, Debian, SUSE, Amazon Linux)

```bash
# Bloquear el módulo
echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif-aead.conf

# Descargar si está cargado
sudo rmmod algif_aead 2>/dev/null || true

# Verificar
grep -c '^algif_aead ' /proc/modules && echo "AÚN CARGADO - requiere reboot" || echo "OK - no cargado"
```

### Para distribuciones EL (RHEL, Rocky, CentOS, Oracle, Fedora, AlmaLinux)

En estas distros el módulo está built-in (`CONFIG_CRYPTO_USER_API_AEAD=y`):

```bash
# Agregar boot parameter
sudo grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"

# REQUIERE REBOOT
sudo reboot

# Verificar después del reboot
grep initcall_blacklist /proc/cmdline
sudo dmesg | grep algif_aead
```

### Para contenedores (Docker/Podman/Kubernetes)

Bloquear AF_ALG via seccomp profile:

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "syscalls": [
    {
      "names": ["socket"],
      "action": "SCMP_ACT_ERRNO",
      "args": [
        {
          "index": 0,
          "value": 38,
          "op": "SCMP_CMP_EQ"
        }
      ]
    }
  ]
}
```

### Revertir mitigación (después de aplicar parche de kernel)

```bash
# Módulo (Ubuntu/Debian/SUSE)
sudo rm /etc/modprobe.d/disable-algif-aead.conf

# Boot param (RHEL/Rocky)
sudo grubby --update-kernel=ALL --remove-args="initcall_blacklist=algif_aead_init"
sudo reboot
```

---

## Ejecución desde PowerShell (Windows)

```powershell
# Instalar dependencias
pip install boto3 paramiko

# Verificar EC2
python check_ec2.py --region us-east-1 --profile mi-perfil

# Verificar VPS remotos
python check_ssh.py --hosts hosts.txt --key C:\Users\mi-user\.ssh\id_rsa

# Verificación completa
python check_all.py --all-regions --ssh-hosts hosts.txt --json | Out-File reporte.json

# Verificar equipo local (solo si tienes WSL)
wsl python3 copyfail-checker/check_local.py
```

---

## Integración con CI/CD

```yaml
# GitHub Actions example
- name: Check Copy Fail vulnerability
  run: |
    pip install boto3
    python copyfail-checker/check_ec2.py --all-regions --json > results.json
    # Fallar si hay vulnerables
    VULN=$(python -c "import json; d=json.load(open('results.json')); print(sum(1 for r in d if r['status']=='VULNERABLE'))")
    if [ "$VULN" -gt "0" ]; then
      echo "::error::$VULN instancias vulnerables a CVE-2026-31431"
      exit 1
    fi
```

---

## Salida JSON

Todos los scripts soportan `--json` para integración programática:

```json
[
  {
    "hostname": "i-0abc123def (web-server)",
    "kernel_version": "6.17.0-1007-aws",
    "distro": "amzn2023",
    "distro_version": "2023",
    "arch": "x86_64",
    "algif_status": "available",
    "mitigation_modprobe": false,
    "mitigation_boot_param": false,
    "status": "VULNERABLE",
    "details": "Kernel 6.17.0-1007-aws vulnerable. Sin mitigación aplicada.",
    "recommendations": [
      "MITIGACIÓN INMEDIATA: echo \"install algif_aead /bin/false\" ...",
      "Actualizar kernel cuando el vendor publique el parche",
      "En contenedores: bloquear AF_ALG via seccomp"
    ]
  }
]
```

---

## Fuentes y Referencias

- [CERT-EU Advisory 2026-005](https://cert.europa.eu/publications/security-advisories/2026-005/)
- [Sysdig: CVE-2026-31431 Analysis](https://www.sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds)
- [Tenable: Copy Fail FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Ubuntu Discourse: Fixes Available](https://discourse.ubuntu.com/t/fixes-available-for-cve-2026-31431-copy-fail/81498)
- [SUSE Response](https://www.suse.com/c/suse-responds-to-the-copy-fail-vulnerability/)
- [CIQ/Rocky Linux Mitigation](https://kb.ciq.com/article/rocky-linux/rl-cve-2026-31431-mitigation)
- [Amazon Linux ALAS](https://explore.alas.aws.amazon.com/CVE-2026-31431.html)
- [Red Hat RHSB-2026-02](https://access.redhat.com/security/vulnerabilities/RHSB-2026-02)
- [copy.fail (disclosure site)](https://copy.fail/)

---

## Licencia

Uso libre. Creado como herramienta de respuesta a incidentes para CVE-2026-31431.
