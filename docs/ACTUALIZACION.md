# Scripts de Actualización

[← Volver al README principal](../README.md)

---

## Actualización EC2

```bash
# Verificar actualizaciones (sin instalar)
python3 update_kernel_ec2.py --region us-east-1 --check-only

# Aplicar actualizaciones
python3 update_kernel_ec2.py --region us-east-1

# Con reboot automático
python3 update_kernel_ec2.py --region us-east-1 --auto-reboot
```

---

## Actualización SSH

```bash
# Verificar actualizaciones
python3 update_kernel_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --check-only

# Aplicar actualizaciones
python3 update_kernel_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa
```

---

[← Volver al README principal](../README.md) | [Siguiente: Automatización →](AUTOMATIZACION.md)
