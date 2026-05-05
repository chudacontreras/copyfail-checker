# Estructura del Proyecto

[← Volver al README principal](../README.md)

---

## Organización de Archivos

```
copyfail-checker/
├── README.md                  # Documentación principal
├── requirements.txt           # Dependencias Python
├── hosts.txt                  # Lista de hosts SSH
│
├── docs/                      # Documentación detallada
│   ├── VULNERABILIDAD.md
│   ├── INSTALACION.md
│   ├── ESTRUCTURA.md
│   ├── VERIFICACION.md
│   ├── MITIGACION.md
│   ├── ACTUALIZACION.md
│   ├── AUTOMATIZACION.md
│   ├── RESULTADOS.md
│   ├── MANUAL.md
│   ├── CICD.md
│   ├── FAQ.md
│   └── REFERENCIAS.md
│
├── lib/                       # Librería compartida
│   ├── __init__.py
│   └── kernel_check.py        # Lógica central
│
├── check_local.py             # Verificación local
├── check_ec2.py               # Verificación EC2
├── check_eks.py               # Verificación EKS
├── check_ecs.py               # Verificación ECS
├── check_ssh.py               # Verificación SSH
├── check_all.py               # Verificación unificada
│
├── mitigate_ec2.py            # Mitigación EC2
├── mitigate_ssh.py            # Mitigación SSH
│
├── update_kernel_ec2.py       # Actualización EC2
├── update_kernel_ssh.py       # Actualización SSH
│
├── monitor_updates.py         # Monitor de actualizaciones
│
├── quick_mitigate.sh          # Script todo-en-uno
├── ci_cd_example.sh           # Ejemplo CI/CD
└── test_setup.sh              # Verificar configuración
```

---

## Scripts de Verificación

### `check_local.py`
- **Propósito**: Verifica el equipo local
- **Uso**: `python3 check_local.py`
- **Requiere**: Ejecutar en Linux

### `check_ec2.py`
- **Propósito**: Verifica instancias EC2
- **Uso**: `python3 check_ec2.py --region us-east-1`
- **Requiere**: boto3, credenciales AWS, SSM Agent

### `check_eks.py`
- **Propósito**: Verifica nodos EKS
- **Uso**: `python3 check_eks.py --region us-east-1`
- **Requiere**: boto3, credenciales AWS, SSM Agent

### `check_ecs.py`
- **Propósito**: Verifica instancias ECS (EC2 launch type)
- **Uso**: `python3 check_ecs.py --region us-east-1`
- **Requiere**: boto3, credenciales AWS, SSM Agent

### `check_ssh.py`
- **Propósito**: Verifica hosts remotos via SSH
- **Uso**: `python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa`
- **Requiere**: paramiko, acceso SSH

### `check_all.py`
- **Propósito**: Ejecuta todos los scripts de verificación
- **Uso**: `python3 check_all.py --all-regions --ssh-hosts hosts.txt`
- **Requiere**: boto3, paramiko

---

## Scripts de Mitigación

### `mitigate_ec2.py`
- **Propósito**: Aplica mitigación en instancias EC2
- **Uso**: `python3 mitigate_ec2.py --region us-east-1`
- **Características**:
  - Detección automática de distribución
  - Modo `--dry-run`
  - Opción `--auto-reboot`

### `mitigate_ssh.py`
- **Propósito**: Aplica mitigación en hosts SSH
- **Uso**: `python3 mitigate_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa`
- **Características**:
  - Detección automática de distribución
  - Modo `--dry-run`
  - Paralelización

---

## Scripts de Actualización

### `update_kernel_ec2.py`
- **Propósito**: Actualiza kernel en instancias EC2
- **Uso**: `python3 update_kernel_ec2.py --region us-east-1`
- **Características**:
  - Modo `--check-only`
  - Opción `--auto-reboot`
  - Soporta múltiples distribuciones

### `update_kernel_ssh.py`
- **Propósito**: Actualiza kernel en hosts SSH
- **Uso**: `python3 update_kernel_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa`
- **Características**:
  - Modo `--check-only`
  - Paralelización
  - Soporta múltiples distribuciones

---

## Scripts de Automatización

### `quick_mitigate.sh`
- **Propósito**: Script interactivo todo-en-uno
- **Uso**: `./quick_mitigate.sh`
- **Características**:
  - Verifica estado
  - Aplica mitigación
  - Verifica resultado
  - Modo `--dry-run`

### `monitor_updates.py`
- **Propósito**: Monitorea disponibilidad de actualizaciones
- **Uso**: `python3 monitor_updates.py --hosts hosts.txt --key ~/.ssh/id_rsa`
- **Características**:
  - Verificación periódica
  - Notificaciones por email/webhook
  - Salida JSON

### `ci_cd_example.sh`
- **Propósito**: Ejemplo de integración CI/CD
- **Uso**: `./ci_cd_example.sh`
- **Características**:
  - Verificación automática
  - Mitigación opcional
  - Generación de reportes

### `test_setup.sh`
- **Propósito**: Verifica configuración del proyecto
- **Uso**: `./test_setup.sh`
- **Características**:
  - Verifica dependencias
  - Verifica archivos
  - Verifica configuración

---

## Librería Compartida

### `lib/kernel_check.py`

Contiene la lógica central compartida por todos los scripts:

- **Funciones de versión**: Comparación de versiones de kernel
- **Detección de distribución**: Identifica la distribución Linux
- **Evaluación de vulnerabilidad**: Determina si un sistema es vulnerable
- **Comandos de verificación**: Scripts shell para ejecutar remotamente
- **Formato de salida**: Funciones para mostrar resultados
- **Datos de distribuciones**: Información sobre parches por distribución

---

## Archivos de Configuración

### `requirements.txt`
```
boto3>=1.26.0
paramiko>=3.0.0
```

### `hosts.txt`
Formato:
```
[usuario@]host[:puerto][|clave_ssh]
```

Ejemplos:
```
192.168.1.100
admin@servidor.com
root@servidor.com:2222
admin@servidor.com|~/.ssh/id_rsa
```

---

## Flujo de Datos

```
┌─────────────────┐
│  Usuario        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Scripts        │
│  (check_*.py)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  lib/           │
│  kernel_check   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Sistemas       │
│  Remotos        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Resultados     │
│  (JSON/Tabla)   │
└─────────────────┘
```

---

## Próximos Pasos

1. **[Verificar si eres vulnerable](VERIFICACION.md)**
2. **[Aplicar mitigación](MITIGACION.md)**
3. **[Configurar automatización](AUTOMATIZACION.md)**

---

[← Volver al README principal](../README.md) | [Siguiente: Verificación →](VERIFICACION.md)
