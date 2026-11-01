#!/usr/bin/env bash
# Regenerates the plain manifests in this directory from the Helm chart's defaults.
#   deploy/k8s/generate.sh          writes 01-config.yaml, 02-deployment.yaml, 03-service.yaml
#   deploy/k8s/generate.sh --check  fails if they differ from what the chart renders (CI uses this)
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="deploy/k8s"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
helm template philter-ai-proxy deploy/helm/philter-ai-proxy \
  --set secrets.existingSecret=philter-ai-proxy-secrets --set serviceAccount.create=false > "$TMP/rendered.yaml"
python3 - "$TMP" <<'PY'
import sys, yaml
tmp = sys.argv[1]
docs = [d for d in yaml.safe_load_all(open(f"{tmp}/rendered.yaml")) if d]
def clean(o):
    if isinstance(o, dict):
        for k in list(o):
            if k in ("helm.sh/chart", "app.kubernetes.io/managed-by", "app.kubernetes.io/version", "checksum/config"):
                del o[k]
            else:
                clean(o[k])
        if "annotations" in o and not o["annotations"]:
            del o["annotations"]
    elif isinstance(o, list):
        for i in o:
            clean(i)
for d in docs:
    clean(d)
by = {d["kind"]: d for d in docs if d["kind"] not in ("Pod", "Service")}
by["Deployment"]["spec"]["template"]["spec"]["serviceAccountName"] = "default"
header = ("# Generated from the Helm chart's defaults by deploy/k8s/generate.sh. Do not edit by hand: change the chart\n"
          "# and regenerate.\n")
def write(name, objects):
    with open(f"{tmp}/{name}", "w") as f:
        f.write(header + "---\n".join(yaml.safe_dump(o, sort_keys=False) for o in objects))
write("01-config.yaml", [by["ConfigMap"], by["PersistentVolumeClaim"]])
write("02-deployment.yaml", [by["Deployment"]])
write("03-service.yaml", [d for d in docs if d["kind"] == "Service"])
PY
if [[ "${1:-}" == "--check" ]]; then
  for f in 01-config.yaml 02-deployment.yaml 03-service.yaml; do
    diff -u "$OUT/$f" "$TMP/$f" || { echo "error: $OUT/$f is out of date; run deploy/k8s/generate.sh" >&2; exit 1; }
  done
  echo "The plain manifests match the chart."
else
  cp "$TMP"/0*.yaml "$OUT/"
fi
