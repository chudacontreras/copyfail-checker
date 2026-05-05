# Automatización

[← Volver al README principal](../README.md)

---

## Script Todo-en-Uno

```bash
# Interactivo
./quick_mitigate.sh

# Simulación
./quick_mitigate.sh --dry-run
```

---

## Monitor de Actualizaciones

```bash
# Manual
python3 monitor_updates.py --hosts hosts.txt --key ~/.ssh/id_rsa

# Cron (diario a las 9 AM)
0 9 * * * cd /ruta/copyfail-checker && python3 monitor_updates.py --hosts hosts.txt --key ~/.ssh/id_rsa
```

---

[← Volver al README principal](../README.md) | [Siguiente: Resultados →](RESULTADOS.md)
