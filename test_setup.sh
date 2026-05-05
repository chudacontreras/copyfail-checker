#!/bin/bash
#
# test_setup.sh - Verifica que todo está configurado correctamente
#
# Este script verifica:
# - Dependencias Python instaladas
# - Archivos de configuración presentes
# - Permisos de archivos
# - Conectividad SSH (opcional)
# - Credenciales AWS (opcional)
#

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC} ${BOLD}CVE-2026-31431 - Verificación de Configuración${NC}              ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}\n"

ERRORS=0
WARNINGS=0

# Función para verificar
check() {
    local name="$1"
    local command="$2"
    local required="$3"
    
    printf "  %-50s" "$name"
    
    if eval "$command" &>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        if [ "$required" = "required" ]; then
            echo -e "${RED}✗ (requerido)${NC}"
            ERRORS=$((ERRORS + 1))
        else
            echo -e "${YELLOW}⚠ (opcional)${NC}"
            WARNINGS=$((WARNINGS + 1))
        fi
        return 1
    fi
}

echo -e "${BOLD}[1/6] Verificando Python y dependencias...${NC}"
check "Python 3" "command -v python3" "required"
check "pip" "command -v pip" "required"
check "boto3" "python3 -c 'import boto3'" "optional"
check "paramiko" "python3 -c 'import paramiko'" "optional"
echo ""

echo -e "${BOLD}[2/6] Verificando archivos del proyecto...${NC}"
check "README.md" "test -f README.md" "required"
check "RESUMEN_EJECUTIVO.md" "test -f RESUMEN_EJECUTIVO.md" "required"
check "QUICK_START.md" "test -f QUICK_START.md" "required"
check "MITIGATION_GUIDE.md" "test -f MITIGATION_GUIDE.md" "required"
check "requirements.txt" "test -f requirements.txt" "required"
check "hosts.txt" "test -f hosts.txt" "optional"
echo ""

echo -e "${BOLD}[3/6] Verificando scripts de verificación...${NC}"
check "check_local.py" "test -f check_local.py" "required"
check "check_ec2.py" "test -f check_ec2.py" "required"
check "check_ssh.py" "test -f check_ssh.py" "required"
check "check_all.py" "test -f check_all.py" "required"
echo ""

echo -e "${BOLD}[4/6] Verificando scripts de mitigación...${NC}"
check "mitigate_ec2.py" "test -f mitigate_ec2.py" "required"
check "mitigate_ssh.py" "test -f mitigate_ssh.py" "required"
check "update_kernel_ec2.py" "test -f update_kernel_ec2.py" "required"
check "update_kernel_ssh.py" "test -f update_kernel_ssh.py" "required"
check "monitor_updates.py" "test -f monitor_updates.py" "required"
echo ""

echo -e "${BOLD}[5/6] Verificando scripts de automatización...${NC}"
check "quick_mitigate.sh" "test -x quick_mitigate.sh" "required"
check "ci_cd_example.sh" "test -x ci_cd_example.sh" "optional"
check "test_setup.sh" "test -x test_setup.sh" "required"
echo ""

echo -e "${BOLD}[6/6] Verificando configuración opcional...${NC}"

# Verificar clave SSH
if [ -f "hosts.txt" ]; then
    SSH_KEY=$(grep -v '^#' hosts.txt | grep '|' | head -1 | cut -d'|' -f2 | tr -d ' ')
    if [ -n "$SSH_KEY" ]; then
        SSH_KEY_EXPANDED="${SSH_KEY/#\~/$HOME}"
        check "Clave SSH ($SSH_KEY)" "test -f $SSH_KEY_EXPANDED" "optional"
    fi
fi

# Verificar AWS CLI
check "AWS CLI" "command -v aws" "optional"

# Verificar credenciales AWS
if command -v aws &>/dev/null; then
    check "Credenciales AWS" "aws sts get-caller-identity" "optional"
fi

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  RESUMEN${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}\n"

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ Configuración básica completa${NC}"
else
    echo -e "${RED}✗ $ERRORS errores encontrados (componentes requeridos faltantes)${NC}"
fi

if [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}⚠ $WARNINGS advertencias (componentes opcionales faltantes)${NC}"
fi

echo ""

# Recomendaciones
if [ $ERRORS -gt 0 ] || [ $WARNINGS -gt 0 ]; then
    echo -e "${BOLD}Recomendaciones:${NC}\n"
    
    if ! python3 -c "import boto3" 2>/dev/null; then
        echo -e "  ${YELLOW}•${NC} Instalar boto3 para scripts AWS:"
        echo -e "    ${CYAN}pip install boto3${NC}"
    fi
    
    if ! python3 -c "import paramiko" 2>/dev/null; then
        echo -e "  ${YELLOW}•${NC} Instalar paramiko para scripts SSH:"
        echo -e "    ${CYAN}pip install paramiko${NC}"
    fi
    
    if [ ! -f "hosts.txt" ]; then
        echo -e "  ${YELLOW}•${NC} Crear archivo hosts.txt con tus servidores SSH"
    fi
    
    if ! command -v aws &>/dev/null; then
        echo -e "  ${YELLOW}•${NC} Instalar AWS CLI para scripts EC2/EKS/ECS:"
        echo -e "    ${CYAN}https://aws.amazon.com/cli/${NC}"
    fi
    
    echo ""
    echo -e "  ${BOLD}O instalar todo de una vez:${NC}"
    echo -e "    ${CYAN}pip install -r requirements.txt${NC}"
    echo ""
fi

# Próximos pasos
echo -e "${BOLD}Próximos pasos:${NC}\n"

if [ $ERRORS -eq 0 ]; then
    echo -e "  ${GREEN}1.${NC} Lee ${BOLD}RESUMEN_EJECUTIVO.md${NC} para entender el plan"
    echo -e "  ${GREEN}2.${NC} Lee ${BOLD}QUICK_START.md${NC} para acción inmediata"
    echo -e "  ${GREEN}3.${NC} Ejecuta ${CYAN}./quick_mitigate.sh${NC} para mitigación automática"
    echo -e "  ${GREEN}4.${NC} O ejecuta manualmente:"
    echo -e "     ${CYAN}python3 check_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa${NC}"
else
    echo -e "  ${RED}1.${NC} Instala las dependencias faltantes"
    echo -e "  ${RED}2.${NC} Ejecuta este script nuevamente: ${CYAN}./test_setup.sh${NC}"
fi

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}\n"

# Exit code
if [ $ERRORS -gt 0 ]; then
    exit 1
else
    exit 0
fi
