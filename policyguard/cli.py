import argparse,json
from dataclasses import asdict
from .scanner import scan_path,sarif
def main():
    p=argparse.ArgumentParser();p.add_argument("path");p.add_argument("--format",choices=["json","sarif","text"],default="text");p.add_argument("--fail-on",choices=["none","low","medium","high"],default="high")
    a=p.parse_args();results=scan_path(a.path)
    if a.format=="json":print(json.dumps([asdict(x) for x in results],indent=2))
    elif a.format=="sarif":print(json.dumps(sarif(results),indent=2))
    else:
        for x in results:print(f"{x.severity.upper()} {x.rule} {x.resource} {x.message}")
        print(f"Found {len(results)} issues")
    rank={"low":1,"medium":2,"high":3}
    if a.fail_on!="none" and any(rank[f.severity]>=rank[a.fail_on] for f in results):raise SystemExit(1)
if __name__=="__main__":main()
