from pathlib import Path
from policyguard.scanner import scan,scan_path,sarif
BASE=Path(__file__).parents[1]
def test_insecure_manifest():
    findings=scan_path(BASE/"examples/insecure.yaml")
    rules={x.rule for x in findings}
    assert {"POD-001","CTR-001","IMG-001","RBAC-001"}.issubset(rules)
    assert len(sarif(findings)["runs"][0]["results"])==len(findings)
def test_secure_manifest():
    assert scan_path(BASE/"examples/secure.yaml")==[]
def test_irrelevant_docs():
    assert scan(None)==[]
    assert scan({"kind":"ConfigMap","metadata":{"name":"settings"}})==[]
def test_role_rbac():
    x=scan({"kind":"Role","rules":[{"verbs":["*"],"resources":["*"]}]})
    assert {v.rule for v in x}=={"RBAC-001","RBAC-002"}
