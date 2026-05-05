# Integración CI/CD

[← Volver al README principal](../README.md)

---

## GitHub Actions

```yaml
- name: Check CVE-2026-31431
  run: |
    pip install boto3
    python3 check_ec2.py --all-regions --json > results.json
```

---

## GitLab CI

```yaml
security_check:
  script:
    - pip install boto3
    - python3 check_ec2.py --all-regions --json > results.json
```

---

[← Volver al README principal](../README.md) | [Siguiente: FAQ →](FAQ.md)
