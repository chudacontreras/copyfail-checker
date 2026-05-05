#!/bin/bash
#
# ci_cd_example.sh - Ejemplo de integración CI/CD para CVE-2026-31431
#
# Este script puede integrarse en tu pipeline de CI/CD para:
# 1. Verificar automáticamente instancias vulnerables
# 2. Aplicar mitigación automáticamente
# 3. Fallar el build si hay instancias vulnerables sin mitigar
# 4. Notificar al equipo
#
# Uso en GitHub Actions, GitLab CI, Jenkins, etc.
#

set -e

# Configuración
AWS_REGION="${AWS_REGION:-us-east-1}"
HOSTS_FILE="${HOSTS_FILE:-hosts.txt}"
SSH_KEY="${SSH_KEY:-~/.ssh/id_rsa}"
AUTO_MITIGATE="${AUTO_MITIGATE:-false}"  # Cambiar a true para mitigación automática
FAIL_ON_VULNERABLE="${FAIL_ON_VULNERABLE:-true}"  # Fallar build si hay vulnerables

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=========================================="
echo "CVE-2026-31431 Security Check"
echo "=========================================="
echo ""

# Instalar dependencias si no están
if ! python3 -c "import boto3" 2>/dev/null; then
    echo "Installing boto3..."
    pip install -q boto3
fi

if ! python3 -c "import paramiko" 2>/dev/null; then
    echo "Installing paramiko..."
    pip install -q paramiko
fi

# Verificar instancias EC2
echo "Checking EC2 instances in $AWS_REGION..."
python3 check_ec2.py --region "$AWS_REGION" --json > ec2_results.json

EC2_VULNERABLE=$(python3 -c "
import json
try:
    with open('ec2_results.json') as f:
        data = json.load(f)
    print(sum(1 for r in data if r.get('status') == 'VULNERABLE'))
except:
    print('0')
")

echo "EC2 vulnerable instances: $EC2_VULNERABLE"

# Verificar servidores SSH (si existe el archivo)
SSH_VULNERABLE=0
if [ -f "$HOSTS_FILE" ] && [ -f "$SSH_KEY" ]; then
    echo "Checking SSH hosts..."
    python3 check_ssh.py --hosts "$HOSTS_FILE" --key "$SSH_KEY" --json > ssh_results.json
    
    SSH_VULNERABLE=$(python3 -c "
import json
try:
    with open('ssh_results.json') as f:
        data = json.load(f)
    print(sum(1 for r in data if r.get('status') == 'VULNERABLE'))
except:
    print('0')
")
    
    echo "SSH vulnerable hosts: $SSH_VULNERABLE"
fi

TOTAL_VULNERABLE=$((EC2_VULNERABLE + SSH_VULNERABLE))

echo ""
echo "=========================================="
echo "Summary"
echo "=========================================="
echo "Total vulnerable systems: $TOTAL_VULNERABLE"
echo ""

# Aplicar mitigación automática si está habilitado
if [ "$AUTO_MITIGATE" = "true" ] && [ "$TOTAL_VULNERABLE" -gt 0 ]; then
    echo -e "${YELLOW}Auto-mitigation enabled. Applying mitigation...${NC}"
    
    if [ "$EC2_VULNERABLE" -gt 0 ]; then
        echo "Mitigating EC2 instances..."
        python3 mitigate_ec2.py --region "$AWS_REGION" --json > ec2_mitigation.json
    fi
    
    if [ "$SSH_VULNERABLE" -gt 0 ] && [ -f "$HOSTS_FILE" ]; then
        echo "Mitigating SSH hosts..."
        python3 mitigate_ssh.py --hosts "$HOSTS_FILE" --key "$SSH_KEY" --json > ssh_mitigation.json
    fi
    
    echo -e "${GREEN}Mitigation applied.${NC}"
    echo ""
    echo "⚠️  Some systems may require reboot to activate mitigation."
    echo "Review the mitigation results and reboot as needed."
fi

# Generar reporte
cat > security_report.md << EOF
# CVE-2026-31431 Security Report

**Date:** $(date)
**Build:** ${CI_BUILD_ID:-N/A}

## Summary

- **Total Vulnerable Systems:** $TOTAL_VULNERABLE
- **EC2 Vulnerable:** $EC2_VULNERABLE
- **SSH Vulnerable:** $SSH_VULNERABLE

## Status

EOF

if [ "$TOTAL_VULNERABLE" -eq 0 ]; then
    cat >> security_report.md << EOF
✅ **All systems are protected**

No vulnerable systems detected.
EOF
    echo -e "${GREEN}✅ All systems are protected${NC}"
    exit 0
else
    cat >> security_report.md << EOF
⚠️ **Vulnerable systems detected**

### Action Required

EOF
    
    if [ "$AUTO_MITIGATE" = "true" ]; then
        cat >> security_report.md << EOF
Automatic mitigation has been applied. Review the results and reboot systems as needed.

**Next Steps:**
1. Review mitigation results in \`ec2_mitigation.json\` and \`ssh_mitigation.json\`
2. Reboot systems that require it
3. Verify mitigation is active
4. Monitor for kernel updates from vendors
EOF
    else
        cat >> security_report.md << EOF
Automatic mitigation is disabled. Manual action required.

**Immediate Actions:**
1. Apply mitigation: \`python3 mitigate_ec2.py --region $AWS_REGION\`
2. Apply mitigation: \`python3 mitigate_ssh.py --hosts $HOSTS_FILE --key $SSH_KEY\`
3. Reboot systems as needed
4. Verify mitigation is active

**Or enable auto-mitigation:**
\`\`\`bash
export AUTO_MITIGATE=true
./ci_cd_example.sh
\`\`\`
EOF
    fi
    
    cat >> security_report.md << EOF

## Detailed Results

### EC2 Instances
\`\`\`json
$(cat ec2_results.json)
\`\`\`

EOF
    
    if [ -f "ssh_results.json" ]; then
        cat >> security_report.md << EOF
### SSH Hosts
\`\`\`json
$(cat ssh_results.json)
\`\`\`
EOF
    fi
    
    echo ""
    echo -e "${RED}⚠️  Vulnerable systems detected${NC}"
    echo ""
    echo "Security report generated: security_report.md"
    
    # Fallar el build si está configurado
    if [ "$FAIL_ON_VULNERABLE" = "true" ]; then
        echo ""
        echo -e "${RED}Build failed due to vulnerable systems${NC}"
        echo "Set FAIL_ON_VULNERABLE=false to allow build to continue"
        exit 1
    fi
fi

echo ""
echo "=========================================="
echo "Security check completed"
echo "=========================================="
