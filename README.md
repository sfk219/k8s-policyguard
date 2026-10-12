# Kubernetes PolicyGuard — Manifest Security Scanner

Runnable Kubernetes YAML static analyzer checking privileged containers, host networking, unsafe security contexts, broad RBAC rules, latest image tags and missing resource limits. Supports text, JSON and SARIF output for CI.

## Run
```bash
pip install -e '.[test]'
python -m policyguard.cli examples/insecure.yaml --format json --fail-on none
python -m policyguard.cli examples/insecure.yaml --format sarif --fail-on none
pytest -q
```
This rule-based scanner is an educational DevSecOps tool, not a Kubernetes security audit or runtime policy enforcement.