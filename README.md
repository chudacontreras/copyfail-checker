# CVE-2026-31431 "Copy Fail" - Suite de Verificación y Mitigación

Suite completa de scripts Python para **verificar, mitigar y actualizar** sistemas Linux vulnerables a **CVE-2026-31431 (Copy Fail)**, una vulnerabilidad crítica de escalación de privilegios local en el kernel Linux.

## 🚨 Inicio Rápido (5 minutos)

```bash
# 1. Instalar dependencias
pip install boto3 paramiko

# 2. Verificar tus servidores
python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa

# 3. Aplicar mitigación automática
./quick_mitigate.sh
```

---

## 📋 Tabla de Contenidos

1. [Sobre la Vulnerabilidad](#sobre-la-vulnerabilidad)
2. [Estructura del Proyecto](#estructura-del-proyecto)
3. [Instalación](#instalación)
4. [Uso Rápido](#uso-rápido)
5. [Scripts de Verificación](#scripts-de-verificación)
6. [Scripts de Mitigación](#scripts-de-mitigación)
7. [Scripts de Actualización](#scripts-de-actualización)
8. [Automatización](#automatización)
9. [Interpretación de Resultados](#interpretación-de-resultados)
10. [Mitigación Manual](#mitigación-manual)
11. [Integración CI/CD](#integración-cicd)
12. [Preguntas Frecuentes](#preguntas-frecuentes)
13. [Referencias](#referencias)

---

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

---

## Estructura del Proyecto

```
copyfail-checker/
├── README.md              # Este archivo
├── requirements.txt       # Dependencias Python
│
├── check_local.py         # Verificación del equipo local
├── check_ec2.py           # Instancias EC2 via SSM
├── check_eks.py           # Nodos EKS via SSM
├── check_ecs.py           # Instancias ECS (EC2) via SSM
├── check_ssh.py           # Hosts remotos via SSH
├── check_all.py           # Script unificado (ejecuta todos)
│
├── mitigate_ec2.py        # Aplica mitigación automática en EC2
├── mitigate_ssh.py        # Aplica mitigación automática via SSH
├── update_kernel_ec2.py   # Actualiza kernel en EC2
├── update_kernel_ssh.py   # Actualiza kernel via SSH
├── monitor_updates.py     # Monitor periódico de actualizaciones
│
├── quick_mitigate.sh      # Script todo-en-uno interactivo
├── ci_cd_example.sh       # Ejemplo de integración CI/CD
├── test_setup.sh          # Verifica configuración
│
└── lib/
    ├── __init__.py
    └── kernel_check.py    # Lógica central compartida
```

---

## Instalación

### Requisitos

- Python 3.8 o superior
- Acceso SSH a servidores remotos (con clave privada)
- Credenciales AWS (opcional, para scripts EC2/EKS/ECS)

### Instalar Dependencias

```bash
# Opción 1: Instalar todo
pip install -r requirements.txt

# Opción 2: Instalar individualmente
pip install boto3      # Para scripts AWS (EC2, EKS, ECS)
pip install paramiko   # Para scripts SSH
```

### Verificar Instalación

```bash
./test_setup.sh
```

---

## Uso Rápido

### Opción 1: Script Automático (Recomendado)

```bash
# Ejecuta todo el flujo automáticamente
./quick_mitigate.sh

# O simular primero (sin cambios reales)
./quick_mitigate.sh --dry-run
```

### Opción 2: Paso a Paso

```bash
# 1. Verificar estado actual
python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa

# 2. Aplicar mitigación
python3 mitigate_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa

# 3. Reiniciar servidores si es necesario
ssh admin@192.168.1.10 -i ~/.ssh/id_rsa 'sudo reboot'

# 4. Verificar mitigación activa
python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa
```

---

## Scripts de Verificación

### `check_local.py` - Equipo Local

Verifica la máquina donde se ejecuta el script.

```bash
# Verificación básica
python3 check_local.py

# Salida JSON
python3 check_local.py --json

# Aplicar mitigación automáticamente (requiere sudo)
sudo python3 check_local.py --mitigate
```

### `check_ec2.py` - Instancias EC2

Verifica instancias EC2 Linux en AWS.

```bash
# Una región
python3 check_ec2.py --region us-east-1

# Todas las regiones
python3 check_ec2.py --all-regions

# Con perfil AWS específico
python3 check_ec2.py --all-regions --profile produccion

# Instancias específicas
python3 check_ec2.py --region us-east-1 --instance-ids i-0abc123,i-0def456

# JSON para integración
python3 check_ec2.py --all-regions --json > ec2_results.json
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

### `check_eks.py` - Nodos EKS

Verifica nodos worker de clusters EKS.

```bash
# Todos los clusters en una región
python3 check_eks.py --region us-east-1

# Cluster específico
python3 check_eks.py --cluster mi-cluster --region us-east-1

# Todas las regiones
python3 check_eks.py --all-regions --profile produccion

# JSON
python3 check_eks.py --all-regions --json > eks_results.json
```

### `check_ecs.py` - Instancias ECS

Verifica instancias EC2 de clusters ECS (tipo EC2 launch type).

```bash
# Todos los clusters en una región
python3 check_ecs.py --region us-east-1

# Cluster específico
python3 check_ecs.py --cluster mi-cluster --region us-east-1

# JSON
python3 check_ecs.py --all-regions --json > ecs_results.json
```

### `check_ssh.py` - Hosts Remotos (SSH)

Para cualquier servidor Linux accesible por SSH: VPS, datacenters, GCP, Azure, etc.

```bash
# Con clave privada (RECOMENDADO)
python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa
python3 check_ssh.py --host 192.168.1.100 --user admin --key ~/.ssh/id_rsa

# Con ssh-agent (claves ya cargadas)
ssh-add ~/.ssh/id_rsa
python3 check_ssh.py --hosts hosts.txt

# Clave con passphrase
python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --passphrase

# Paralelismo personalizado
python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --threads 20

# JSON
python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --json > ssh_results.json
```

**Formato del archivo `hosts.txt`:**
```
# Comentarios con #
# Formato básico: [usuario@]host[:puerto]

192.168.1.100
mi-servidor.ejemplo.com

# Con usuario específico
admin@vps1.digitalocean.com
ubuntu@10.0.0.5

# Con puerto personalizado
root@servidor.ejemplo.com:2222

# Con clave privada por host (separador |)
admin@vps-digital.com|~/.ssh/id_digitalocean
deploy@gcp-instance.com:22|~/.ssh/gcp_key
```

### `check_all.py` - Verificación Unificada

Ejecuta todos los scripts y genera un reporte consolidado.

```bash
# AWS + local
python3 check_all.py --region us-east-1

# Todo: AWS (todas las regiones) + SSH + local
python3 check_all.py --all-regions --profile prod --ssh-hosts hosts.txt --ssh-key ~/.ssh/id_rsa

# Solo SSH + local (sin AWS)
python3 check_all.py --skip-aws --ssh-hosts hosts.txt

# JSON consolidado
python3 check_all.py --all-regions --ssh-hosts hosts.txt --json > reporte_completo.json
```

---

## Scripts de Mitigación

### `mitigate_ec2.py` - Mitigación en EC2

Aplica mitigación automática en instancias EC2 vulnerables.

```bash
# Simular primero (dry-run)
python3 mitigate_ec2.py --region us-east-1 --dry-run

# Aplicar mitigación
python3 mitigate_ec2.py --region us-east-1

# Con reboot automático
python3 mitigate_ec2.py --region us-east-1 --auto-reboot

# Todas las regiones
python3 mitigate_ec2.py --all-regions --profile produccion

# Instancias específicas
python3 mitigate_ec2.py --region us-east-1 --instance-ids i-0abc123,i-0def456

# JSON
python3 mitigate_ec2.py --region us-east-1 --json > mitigation_results.json
```

**Características:**
- ✅ Detección automática de distribución
- ✅ Aplica mitigación apropiada (modprobe o boot param)
- ✅ Modo `--dry-run` para simular
- ✅ Opción `--auto-reboot`
- ✅ Salida JSON

### `mitigate_ssh.py` - Mitigación en SSH

Aplica mitigación automática en hosts remotos via SSH.

```bash
# Simular primero
python3 mitigate_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --dry-run

# Aplicar mitigación
python3 mitigate_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa

# Host individual
python3 mitigate_ssh.py --host 192.168.1.100 --user admin --key ~/.ssh/id_rsa

# Con clave protegida por passphrase
python3 mitigate_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --passphrase

# Paralelismo personalizado
python3 mitigate_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --threads 20

# JSON
python3 mitigate_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --json > results.json
```

---

## Scripts de Actualización

### `update_kernel_ec2.py` - Actualización de Kernel en EC2

Actualiza el kernel cuando el parche esté disponible.

```bash
# Verificar si hay actualizaciones (sin instalar)
python3 update_kernel_ec2.py --region us-east-1 --check-only

# Aplicar actualizaciones
python3 update_kernel_ec2.py --region us-east-1

# Con reboot automático
python3 update_kernel_ec2.py --region us-east-1 --auto-reboot

# Todas las regiones
python3 update_kernel_ec2.py --all-regions --profile produccion

# JSON
python3 update_kernel_ec2.py --region us-east-1 --json > update_results.json
```

### `update_kernel_ssh.py` - Actualización de Kernel en SSH

Actualiza el kernel en hosts remotos.

```bash
# Verificar si hay actualizaciones
python3 update_kernel_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --check-only

# Aplicar actualizaciones
python3 update_kernel_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa

# Host individual
python3 update_kernel_ssh.py --host 192.168.1.100 --user admin --key ~/.ssh/id_rsa

# JSON
python3 update_kernel_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --json > results.json
```

---

## Automatización

### `quick_mitigate.sh` - Script Todo-en-Uno

Script interactivo que ejecuta todo el flujo de mitigación.

```bash
# Interactivo
./quick_mitigate.sh

# Simulación (sin cambios)
./quick_mitigate.sh --dry-run
```

### `monitor_updates.py` - Monitor de Actualizaciones

Verifica periódicamente si hay actualizaciones de kernel disponibles.

```bash
# Ejecutar manualmente
python3 monitor_updates.py --region us-east-1 --hosts hosts.txt --key ~/.ssh/id_rsa

# Con notificaciones por email
python3 monitor_updates.py --hosts hosts.txt --key ~/.ssh/id_rsa --notify-email admin@example.com

# Configurar en cron (verificar diariamente a las 9 AM)
crontab -e
# Agregar:
0 9 * * * cd /ruta/a/copyfail-checker && python3 monitor_updates.py --hosts hosts.txt --key ~/.ssh/id_rsa >> /var/log/copyfail-monitor.log 2>&1
```

### `ci_cd_example.sh` - Integración CI/CD

Ejemplo de integración en pipelines de CI/CD.

```bash
# Con mitigación automática
export AUTO_MITIGATE=true
./ci_cd_example.sh

# Sin mitigación automática (solo alertar)
export AUTO_MITIGATE=false
./ci_cd_example.sh
```

---

## Interpretación de Resultados

| Estado | Significado | Acción |
|--------|-------------|--------|
| 🔴 **VULNERABLE** | Kernel vulnerable, sin mitigación | **Aplicar mitigación AHORA** |
| 🟠 **PROBABLEMENTE VULNERABLE** | No se pudo verificar kernel exacto | Habilitar SSM/SSH para verificación exacta |
| 🟡 **MITIGADO** | Kernel vulnerable pero mitigación aplicada | Esperar parche del vendor |
| 🟢 **NO VULNERABLE** | Kernel parcheado o no afectado | Ninguna acción necesaria |
| ⚪ **DESCONOCIDO** | No se pudo conectar o verificar | Verificar conectividad |

---

## Mitigación Manual

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

En estas distros el módulo está built-in:

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

## Integración CI/CD

### Ejemplo GitHub Actions

```yaml
name: CVE-2026-31431 Security Check

on:
  schedule:
    - cron: '0 9 * * *'  # Diario a las 9 AM
  workflow_dispatch:

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install dependencies
        run: pip install boto3
      
      - name: Check EC2 instances
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          python3 check_ec2.py --all-regions --json > results.json
          VULN=$(python3 -c "import json; d=json.load(open('results.json')); print(sum(1 for r in d if r['status']=='VULNERABLE'))")
          if [ "$VULN" -gt "0" ]; then
            echo "::error::$VULN instancias vulnerables a CVE-2026-31431"
            exit 1
          fi
```

### Ejemplo GitLab CI

```yaml
security_check:
  stage: test
  script:
    - pip install boto3
    - python3 check_ec2.py --all-regions --json > results.json
    - |
      VULN=$(python3 -c "import json; d=json.load(open('results.json')); print(sum(1 for r in d if r['status']=='VULNERABLE'))")
      if [ "$VULN" -gt "0" ]; then
        echo "$VULN instancias vulnerables"
        exit 1
      fi
  only:
    - schedules
```

---

## Preguntas Frecuentes

### ¿Cuándo debo aplicar la mitigación?

**AHORA.** La mitigación es temporal pero efectiva. Aplícala inmediatamente mientras esperas el parche oficial.

### ¿La mitigación afecta el rendimiento?

**No.** Solo bloquea el módulo `algif_aead` que raramente se usa. Solo afecta IPsec con ESN y algunas configuraciones de cryptsetup.

### ¿Necesito reiniciar después de la mitigación?

**Depende:**
- **Distros con módulo cargable:** Si el módulo no está en uso, no requiere reboot
- **Distros EL (kernel built-in):** Siempre requiere reboot

Los scripts te indicarán si necesitas reiniciar.

### ¿Cuándo debo actualizar el kernel?

Cuando tu distribución publique el parche oficial. Verifica con:
```bash
python3 update_kernel_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --check-only
```

### ¿Puedo revertir la mitigación?

Sí, después de actualizar el kernel:
```bash
# Distros con módulo
sudo rm /etc/modprobe.d/disable-algif-aead.conf

# Distros EL
sudo grubby --update-kernel=ALL --remove-args="initcall_blacklist=algif_aead_init"
sudo reboot
```

### ¿Los scripts son seguros?

Sí. Los scripts:
- Usan autenticación por clave SSH
- Tienen modo `--dry-run` para simular
- No eliminan ni modifican datos
- Solo aplican configuraciones de seguridad estándar

### ¿Qué pasa si algo sale mal?

Los scripts son idempotentes (puedes ejecutarlos múltiples veces). Si algo falla:
1. Revisa los logs de salida
2. Verifica conectividad SSH/SSM
3. Verifica permisos sudo en los hosts
4. Ejecuta manualmente los comandos en un host de prueba

---

## Referencias

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

---

## Soporte

Para reportar problemas o sugerir mejoras, abre un issue en el repositorio.
