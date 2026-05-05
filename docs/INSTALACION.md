# Instalación y Configuración

[← Volver al README principal](../README.md)

---

## Requisitos del Sistema

### Python
- **Versión mínima**: Python 3.8
- **Recomendado**: Python 3.10 o superior

### Sistemas Operativos

#### Para ejecutar los scripts:
- Linux (cualquier distribución)
- macOS (para scripts remotos)
- Windows con WSL (para scripts remotos)

#### Para verificar vulnerabilidad:
- Solo sistemas Linux (el kernel Linux es el afectado)

---

## Dependencias Python

### Instalación Rápida

```bash
# Instalar todas las dependencias
pip install -r requirements.txt
```

### Instalación Individual

```bash
# Para scripts AWS (EC2, EKS, ECS)
pip install boto3

# Para scripts SSH (servidores remotos)
pip install paramiko
```

### Verificar Instalación

```bash
# Verificar boto3
python3 -c "import boto3; print('boto3:', boto3.__version__)"

# Verificar paramiko
python3 -c "import paramiko; print('paramiko:', paramiko.__version__)"
```

---

## Configuración AWS (Opcional)

Solo necesario si vas a usar scripts de EC2/EKS/ECS.

### Opción 1: AWS CLI

```bash
# Instalar AWS CLI
# Ubuntu/Debian
sudo apt install awscli

# macOS
brew install awscli

# Configurar credenciales
aws configure
```

### Opción 2: Variables de Entorno

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

### Opción 3: Perfil Nombrado

```bash
# Configurar perfil
aws configure --profile produccion

# Usar en scripts
python3 check_ec2.py --profile produccion --region us-east-1
```

### Permisos IAM Necesarios

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeImages",
        "ec2:DescribeRegions",
        "ec2:RebootInstances",
        "ssm:DescribeInstanceInformation",
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "eks:ListClusters",
        "eks:DescribeNodegroup",
        "eks:ListNodegroups",
        "ecs:ListClusters",
        "ecs:ListContainerInstances",
        "ecs:DescribeContainerInstances",
        "autoscaling:DescribeAutoScalingGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Configuración SSH

### Generar Clave SSH (si no tienes una)

```bash
# Ed25519 (recomendado)
ssh-keygen -t ed25519 -C "tu_email@ejemplo.com"

# RSA (alternativa)
ssh-keygen -t rsa -b 4096 -C "tu_email@ejemplo.com"
```

### Copiar Clave a Servidores

```bash
# Copiar clave pública
ssh-copy-id -i ~/.ssh/id_ed25519.pub usuario@servidor.com

# O manualmente
cat ~/.ssh/id_ed25519.pub | ssh usuario@servidor.com "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

### Configurar ssh-agent (Opcional)

```bash
# Iniciar ssh-agent
eval "$(ssh-agent -s)"

# Agregar clave
ssh-add ~/.ssh/id_ed25519

# Verificar claves cargadas
ssh-add -l
```

---

## Configurar hosts.txt

Crea o edita el archivo `hosts.txt` con tus servidores:

```bash
# Formato básico
192.168.1.100
servidor.ejemplo.com

# Con usuario específico
admin@vps1.ejemplo.com
ubuntu@10.0.0.5

# Con puerto personalizado
root@servidor.ejemplo.com:2222

# Con clave SSH específica por host
admin@vps1.ejemplo.com|~/.ssh/id_digitalocean
deploy@vps2.ejemplo.com:22|~/.ssh/id_gcp
```

### Ejemplo Completo

```bash
# Servidores de producción
admin@web-server-1.ejemplo.com|~/.ssh/id_prod
admin@web-server-2.ejemplo.com|~/.ssh/id_prod
admin@api-server.ejemplo.com:2222|~/.ssh/id_prod

# Servidores de desarrollo
ubuntu@dev-server.ejemplo.com|~/.ssh/id_dev

# VPS externos
root@vps.digitalocean.com|~/.ssh/id_digitalocean
```

---

## Verificar Configuración

### Script Automático

```bash
./test_setup.sh
```

### Verificación Manual

```bash
# 1. Verificar Python
python3 --version

# 2. Verificar dependencias
python3 -c "import boto3, paramiko; print('OK')"

# 3. Verificar AWS (si aplica)
aws sts get-caller-identity

# 4. Verificar SSH
ssh -T usuario@servidor.ejemplo.com

# 5. Verificar archivos
ls -la check_*.py mitigate_*.py update_*.py
```

---

## Configuración Avanzada

### Configurar Timeout SSH

Edita `~/.ssh/config`:

```
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3
    ConnectTimeout 10
```

### Configurar Paralelismo

Los scripts SSH soportan paralelismo:

```bash
# Procesar 20 hosts simultáneamente
python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --threads 20
```

### Configurar Logging

```bash
# Redirigir salida a archivo
python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa > verificacion.log 2>&1

# Con timestamp
python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa | tee "verificacion_$(date +%Y%m%d_%H%M%S).log"
```

---

## Solución de Problemas

### Error: "boto3 not found"

```bash
pip install boto3
# O con pip3
pip3 install boto3
```

### Error: "paramiko not found"

```bash
pip install paramiko
# O con pip3
pip3 install paramiko
```

### Error: "Permission denied (publickey)"

```bash
# Verificar que la clave existe
ls -la ~/.ssh/id_rsa

# Verificar permisos
chmod 600 ~/.ssh/id_rsa
chmod 700 ~/.ssh

# Probar conexión
ssh -v usuario@servidor.ejemplo.com
```

### Error: "No credentials found"

```bash
# Configurar AWS
aws configure

# O usar variables de entorno
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
```

### Error: "SSM Agent not available"

En instancias EC2:
1. Verificar que SSM Agent está instalado
2. Verificar que la instancia tiene rol IAM con `AmazonSSMManagedInstanceCore`
3. Verificar conectividad de red

---

## Instalación en Diferentes Sistemas

### Ubuntu/Debian

```bash
# Actualizar sistema
sudo apt update

# Instalar Python y pip
sudo apt install python3 python3-pip

# Instalar dependencias
pip3 install boto3 paramiko

# Instalar AWS CLI (opcional)
sudo apt install awscli
```

### RHEL/CentOS/Rocky/AlmaLinux

```bash
# Instalar Python y pip
sudo dnf install python3 python3-pip

# Instalar dependencias
pip3 install boto3 paramiko

# Instalar AWS CLI (opcional)
sudo dnf install awscli
```

### macOS

```bash
# Instalar Homebrew (si no lo tienes)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Instalar Python
brew install python3

# Instalar dependencias
pip3 install boto3 paramiko

# Instalar AWS CLI (opcional)
brew install awscli
```

### Windows (WSL)

```bash
# Instalar WSL (PowerShell como administrador)
wsl --install

# Dentro de WSL
sudo apt update
sudo apt install python3 python3-pip
pip3 install boto3 paramiko
```

---

## Próximos Pasos

1. **[Ver estructura del proyecto](ESTRUCTURA.md)**
2. **[Verificar si eres vulnerable](VERIFICACION.md)**
3. **[Aplicar mitigación](MITIGACION.md)**

---

[← Volver al README principal](../README.md) | [Siguiente: Estructura del Proyecto →](ESTRUCTURA.md)
