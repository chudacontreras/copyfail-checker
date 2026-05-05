# Scripts de Mitigación

[← Volver al README principal](../README.md)

---

## Mitigación EC2

```bash
# Simular (dry-run)
python3 mitigate_ec2.py --region us-east-1 --dry-run

# Aplicar
python3 mitigate_ec2.py --region us-east-1

# Con reboot automático
python3 mitigate_ec2.py --region us-east-1 --auto-reboot

# Todas las regiones
python3 mitigate_ec2.py --all-regions

# JSON
python3 mitigate_ec2.py --region us-east-1 --json > results.json
```

---

## Mitigación SSH

```bash
# Simular (dry-run)
python3 mitigate_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --dry-run

# Aplicar
python3 mitigate_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa

# Host individual
python3 mitigate_ssh.py --host 192.168.1.100 --user admin --key ~/.ssh/id_rsa

# JSON
python3 mitigate_ssh.py --hosts hosts.txt --key ~/.ssh/id_rsa --json > results.json
```

---

[← Volver al README principal](../README.md) | [Siguiente: Actualización →](ACTUALIZACION.md)
