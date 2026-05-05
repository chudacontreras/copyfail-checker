#!/bin/bash
#
# quick_mitigate.sh - Script rápido para mitigar CVE-2026-31431 en tus servidores
#
# Este script ejecuta el flujo completo de mitigación:
# 1. Verifica estado actual
# 2. Aplica mitigación
# 3. Muestra resumen
#
# Uso:
#   ./quick_mitigate.sh
#   ./quick_mitigate.sh --dry-run  # Solo simular
#

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuración (ajusta según tus necesidades)
HOSTS_FILE="hosts.txt"
SSH_KEY="~/.ssh/id_rsa"
AWS_REGION="us-east-1"
AWS_PROFILE=""  # Dejar vacío si usas el perfil default

# Parsear argumentos
DRY_RUN=""
if [[ "$1" == "--dry-run" ]]; then
    DRY_RUN="--dry-run"
    echo -e "${YELLOW}MODO DRY RUN - Solo simulación, sin cambios reales${NC}\n"
fi

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC} ${BOLD}CVE-2026-31431 (Copy Fail) - Mitigación Automática${NC}           ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}\n"

# Verificar dependencias
echo -e "${BOLD}[1/5] Verificando dependencias...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: python3 no está instalado${NC}"
    exit 1
fi

if ! python3 -c "import paramiko" 2>/dev/null; then
    echo -e "${YELLOW}⚠ paramiko no está instalado. Instalando...${NC}"
    pip install paramiko
fi

if ! python3 -c "import boto3" 2>/dev/null; then
    echo -e "${YELLOW}⚠ boto3 no está instalado. Instalando...${NC}"
    pip install boto3
fi

echo -e "${GREEN}✓ Dependencias OK${NC}\n"

# Verificar estado actual
echo -e "${BOLD}[2/5] Verificando estado actual de los servidores...${NC}"

# SSH Servers
if [ -f "$HOSTS_FILE" ]; then
    echo -e "${CYAN}Servidores SSH:${NC}"
    python3 check_ssh.py --hosts "$HOSTS_FILE" --key "$SSH_KEY" 2>/dev/null || echo -e "${YELLOW}⚠ No se pudieron verificar servidores SSH${NC}"
    echo ""
fi

# AWS EC2 (si está configurado)
if command -v aws &> /dev/null; then
    echo -e "${CYAN}Instancias EC2:${NC}"
    AWS_ARGS="--region $AWS_REGION"
    if [ -n "$AWS_PROFILE" ]; then
        AWS_ARGS="$AWS_ARGS --profile $AWS_PROFILE"
    fi
    python3 check_ec2.py $AWS_ARGS 2>/dev/null || echo -e "${YELLOW}⚠ No se pudieron verificar instancias EC2${NC}"
    echo ""
fi

# Confirmar antes de aplicar (si no es dry-run)
if [ -z "$DRY_RUN" ]; then
    echo -e "${YELLOW}${BOLD}¿Deseas aplicar la mitigación ahora? (s/N)${NC} "
    read -r response
    if [[ ! "$response" =~ ^[Ss]$ ]]; then
        echo -e "${YELLOW}Operación cancelada${NC}"
        exit 0
    fi
    echo ""
fi

# Aplicar mitigación
echo -e "${BOLD}[3/5] Aplicando mitigación...${NC}\n"

# SSH Servers
if [ -f "$HOSTS_FILE" ]; then
    echo -e "${CYAN}Mitigando servidores SSH...${NC}"
    python3 mitigate_ssh.py --hosts "$HOSTS_FILE" --key "$SSH_KEY" $DRY_RUN
    echo ""
fi

# AWS EC2
if command -v aws &> /dev/null; then
    echo -e "${CYAN}Mitigando instancias EC2...${NC}"
    python3 mitigate_ec2.py $AWS_ARGS $DRY_RUN
    echo ""
fi

# Verificar resultado
if [ -z "$DRY_RUN" ]; then
    echo -e "${BOLD}[4/5] Verificando resultado...${NC}\n"
    
    if [ -f "$HOSTS_FILE" ]; then
        echo -e "${CYAN}Estado de servidores SSH:${NC}"
        python3 check_ssh.py --hosts "$HOSTS_FILE" --key "$SSH_KEY" 2>/dev/null || true
        echo ""
    fi
    
    if command -v aws &> /dev/null; then
        echo -e "${CYAN}Estado de instancias EC2:${NC}"
        python3 check_ec2.py $AWS_ARGS 2>/dev/null || true
        echo ""
    fi
fi

# Resumen final
echo -e "${BOLD}[5/5] Resumen${NC}\n"

if [ -z "$DRY_RUN" ]; then
    echo -e "${GREEN}✓ Mitigación aplicada${NC}"
    echo ""
    echo -e "${YELLOW}${BOLD}IMPORTANTE:${NC}"
    echo -e "  • Algunos servidores pueden requerir ${BOLD}REBOOT${NC} para activar la mitigación"
    echo -e "  • Revisa la salida anterior para identificar cuáles necesitan reboot"
    echo -e "  • Para reiniciar manualmente:"
    echo -e "    ${CYAN}ssh user@host -i ~/.ssh/key 'sudo reboot'${NC}"
    echo ""
    echo -e "${BOLD}Próximos pasos:${NC}"
    echo -e "  1. Reiniciar servidores que lo requieran"
    echo -e "  2. Verificar que la mitigación está activa (ejecutar check_* nuevamente)"
    echo -e "  3. Cuando el vendor publique el parche, ejecutar:"
    echo -e "     ${CYAN}python3 update_kernel_ssh.py --hosts $HOSTS_FILE --key $SSH_KEY${NC}"
    echo -e "     ${CYAN}python3 update_kernel_ec2.py $AWS_ARGS${NC}"
else
    echo -e "${YELLOW}✓ Simulación completada (no se aplicaron cambios)${NC}"
    echo -e "  Para aplicar los cambios reales, ejecuta sin --dry-run:"
    echo -e "  ${CYAN}./quick_mitigate.sh${NC}"
fi

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC} ${GREEN}Proceso completado${NC}                                             ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
