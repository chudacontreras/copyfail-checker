# Sobre la Vulnerabilidad CVE-2026-31431 "Copy Fail"

[← Volver al README principal](../README.md)

---

## Información General

| Campo | Detalle |
|-------|---------|
| **CVE** | CVE-2026-31431 |
| **Nombre** | Copy Fail |
| **CVSS** | 7.8 (HIGH) |
| **Vector** | CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| **Tipo** | Local Privilege Escalation (LPE) |
| **Componente** | `algif_aead` - módulo AEAD del crypto API del kernel (AF_ALG) |
| **Introducida** | Julio 2017 (commit `72548b093ee3`) |
| **Kernels vulnerables** | 4.14 hasta 6.18.21, 6.19.11, y anteriores a 7.0 |
| **Kernels parcheados** | 7.0+, 6.19.12+, 6.18.22+ |
| **Exploit público** | Sí (~732 bytes Python, funciona sin race conditions) |
| **CISA KEV** | Añadido (explotación activa confirmada) |

---

## ¿Cómo Funciona?

Un usuario local sin privilegios puede corromper el page cache de binarios setuid (como `/usr/bin/su`) usando operaciones `splice()` + `AF_ALG` socket, obteniendo root en segundos.

### Características del Exploit

- ✅ **100% confiable** - No requiere race conditions
- ✅ **Muy pequeño** - ~732 bytes de código Python
- ✅ **Rápido** - Obtiene root en segundos
- ✅ **Silencioso** - Difícil de detectar
- ⚠️ **Público** - Exploit disponible en Internet

### Diferencias con Otras Vulnerabilidades

| Vulnerabilidad | Race Condition | Confiabilidad | Complejidad |
|----------------|----------------|---------------|-------------|
| **Copy Fail** | ❌ No | 100% | Baja |
| Dirty Pipe | ✅ Sí | ~90% | Media |
| Dirty COW | ✅ Sí | ~80% | Alta |

---

## Distribuciones Afectadas

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

---

## Nota Importante sobre Distribuciones EL

En distribuciones Enterprise Linux (RHEL, Rocky, CentOS, Oracle, Fedora, AlmaLinux), `algif_aead` está compilado directamente en el kernel (`CONFIG_CRYPTO_USER_API_AEAD=y`), **no como módulo**.

Esto significa que:
- ❌ `rmmod` no funciona
- ❌ `/etc/modprobe.d/` no funciona
- ✅ Se requiere boot parameter: `initcall_blacklist=algif_aead_init`

### Mitigación Correcta para EL

```bash
sudo grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"
sudo reboot
```

---

## Impacto en Contenedores

### Docker/Podman/Kubernetes

Los contenedores **comparten el kernel del host**, por lo que:

- ⚠️ Un contenedor comprometido puede explotar Copy Fail
- ⚠️ Puede escapar del contenedor y obtener root en el host
- ⚠️ Afecta a todos los contenedores en el mismo host

### Mitigación para Contenedores

Bloquear AF_ALG via seccomp profile (ver [Mitigación Manual](MANUAL.md#para-contenedores)).

---

## Impacto en la Nube

### AWS EKS
- Los nodos EKS comparten kernel con todos los pods
- Un pod comprometido puede explotar Copy Fail para escape de contenedor
- Aplicar seccomp profiles para bloquear AF_ALG en pods no confiables

### AWS ECS
- Instancias EC2: Vulnerables (aplicar mitigación)
- Fargate: Gestionado por AWS (contactar soporte para status)

### AWS EC2
- Todas las instancias Linux son potencialmente vulnerables
- Verificar con SSM o scripts de verificación

---

## Línea de Tiempo

| Fecha | Evento |
|-------|--------|
| **Julio 2017** | Vulnerabilidad introducida en kernel 4.14 |
| **Abril 2026** | Vulnerabilidad descubierta y reportada |
| **1 Mayo 2026** | Disclosure público |
| **3 Mayo 2026** | SUSE publica parches |
| **4 Mayo 2026** | CISA añade a KEV (explotación activa) |
| **Presente** | Parches en progreso para la mayoría de distros |

---

## Severidad y Prioridad

### CVSS 7.8 (HIGH)

**¿Por qué es crítico?**
- ✅ Exploit público disponible
- ✅ 100% confiable (no race conditions)
- ✅ Explotación activa confirmada (CISA KEV)
- ✅ Afecta kernels desde 2017 (millones de sistemas)
- ✅ Fácil de explotar (732 bytes de código)

### Recomendación

**Aplicar mitigación INMEDIATAMENTE** mientras esperas el parche oficial.

---

## Detección

### ¿Cómo saber si fui comprometido?

La explotación es difícil de detectar, pero puedes buscar:

```bash
# Verificar logs del sistema
sudo journalctl -xe | grep -i "algif\|splice\|AF_ALG"

# Verificar procesos sospechosos
ps aux | grep -i "algif\|aead"

# Verificar modificaciones recientes en binarios setuid
find /usr/bin /usr/sbin -perm -4000 -mtime -7 -ls
```

---

## Próximos Pasos

1. **[Verificar si eres vulnerable](VERIFICACION.md)**
2. **[Aplicar mitigación inmediata](MITIGACION.md)**
3. **[Configurar monitoreo](AUTOMATIZACION.md)**
4. **[Actualizar cuando esté disponible](ACTUALIZACION.md)**

---

[← Volver al README principal](../README.md) | [Siguiente: Instalación →](INSTALACION.md)
