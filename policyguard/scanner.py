"""Static security checks for Kubernetes YAML, not a runtime scanner."""
from dataclasses import dataclass,asdict
from pathlib import Path
import yaml

@dataclass(frozen=True)
class Finding:
    rule:str
    severity:str
    resource:str
    message:str
    file:str

def pod_spec(doc):
    kind=doc.get("kind","");spec=doc.get("spec") or {}
    if kind=="Pod":return spec
    if kind in ("Deployment","StatefulSet","DaemonSet","ReplicaSet","Job"):
        return ((spec.get("template") or {}).get("spec") or {})
    if kind=="CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    return None

def scan(doc,filename="<memory>"):
    if not isinstance(doc,dict) or not doc.get("kind"):return []
    kind=doc["kind"];ref=f'{kind}/{(doc.get("metadata") or {}).get("name","unnamed")}'
    found=[]
    def add(code,severity,message):found.append(Finding(code,severity,ref,message,filename))
    if kind in ("Role","ClusterRole"):
        for item in doc.get("rules") or []:
            if "*" in item.get("verbs",[]):add("RBAC-001","high","Wildcard RBAC verbs")
            if "*" in item.get("resources",[]):add("RBAC-002","medium","Wildcard RBAC resources")
    pod=pod_spec(doc)
    if pod is None:return found
    if pod.get("hostNetwork"):add("POD-001","high","Host networking enabled")
    if pod.get("hostPID"):add("POD-002","high","Host PID namespace enabled")
    if any("hostPath" in v for v in pod.get("volumes",[])):add("POD-003","high","Host path mount")
    if (pod.get("securityContext") or {}).get("runAsNonRoot") is not True:add("POD-004","medium","Non-root execution not enforced")
    for item in (pod.get("containers") or [])+(pod.get("initContainers") or []):
        name=item.get("name","unnamed");sec=item.get("securityContext") or {}
        if sec.get("privileged") is True:add("CTR-001","high",name+": privileged container")
        if sec.get("allowPrivilegeEscalation") is not False:add("CTR-002","medium",name+": privilege escalation not disabled")
        if sec.get("readOnlyRootFilesystem") is not True:add("CTR-003","low",name+": writable root filesystem")
        image=item.get("image","")
        if ":" not in image.split("/")[-1] or image.endswith(":latest"):add("IMG-001","medium",name+": unpinned image version")
        if not item.get("readinessProbe"):add("OBS-001","low",name+": missing readiness probe")
        resources=item.get("resources") or {}
        if not all(k in (resources.get("limits") or {}) for k in ("memory","cpu")):add("RES-001","medium",name+": resource limits incomplete")
    return found

def scan_path(path):
    source=Path(path);files=sorted(list(source.rglob("*.yaml"))+list(source.rglob("*.yml"))) if source.is_dir() else [source]
    results=[]
    for filename in files:
        with open(filename,encoding="utf8") as handle:
            for doc in yaml.safe_load_all(handle):results+=scan(doc,str(filename))
    return sorted(results,key=lambda a:(a.file,a.resource,a.rule))

def sarif(findings):
    return {"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"K8s PolicyGuard","rules":[{"id":r} for r in sorted({f.rule for f in findings})]}},"results":[{"ruleId":f.rule,"level":"error" if f.severity=="high" else "warning","message":{"text":f.resource+": "+f.message},"locations":[{"physicalLocation":{"artifactLocation":{"uri":f.file}}}]} for f in findings]}]}
