#!/usr/bin/env bash
# Build config/ids-controller.kubeconfig from the ids-controller service-account
# token, so the backend talks to the API server with least privilege instead of
# the admin kubeconfig. Revoke by deleting secret ids-controller-token.
#   create-kubeconfig.sh                                   # ids-controller (deception)
#   create-kubeconfig.sh ids-traffic ids-attack-generator-token config/ids-attack-generator.kubeconfig
set -euo pipefail
cd "$(dirname "$0")/../.."
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
NS="${1:-ids-deception}"
SECRET="${2:-ids-controller-token}"
OUT="${3:-config/ids-controller.kubeconfig}"
USER_NAME="${SECRET%-token}"

for _ in $(seq 30); do
    TOKEN=$(kubectl -n "$NS" get secret "$SECRET" -o jsonpath='{.data.token}' 2>/dev/null | base64 -d || true)
    [ -n "$TOKEN" ] && break
    sleep 1
done
[ -n "$TOKEN" ] || { echo "token not populated"; exit 1; }
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
CA=$(kubectl -n "$NS" get secret "$SECRET" -o jsonpath='{.data.ca\.crt}')

umask 077
cat > "$OUT" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: k3s
  cluster:
    server: $SERVER
    certificate-authority-data: $CA
users:
- name: $USER_NAME
  user:
    token: $TOKEN
contexts:
- name: $USER_NAME
  context: {cluster: k3s, user: $USER_NAME, namespace: $NS}
current-context: $USER_NAME
EOF
echo "wrote $OUT"
