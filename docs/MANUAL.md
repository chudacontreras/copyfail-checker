# Mitigación Manual

[← Volver al README principal](../README.md)

---

## Distribuciones con Módulo Cargable

Ubuntu, Debian, SUSE, Amazon Linux:

```bash
echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif-aead.conf
sudo rmmod algif_aead 2>/dev/null || true
```

---

## Distribuciones EL

RHEL, Rocky, CentOS, Oracle, Fedora:

```bash
sudo grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"
sudo reboot
```

---

[← Volver al README principal](../README.md) | [Siguiente: CI/CD →](CICD.md)
