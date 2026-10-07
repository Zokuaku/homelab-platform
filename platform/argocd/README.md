# platform/argocd — Argo CD self-managed config

Argo CD manages its **own configuration** from here via the `argocd-config` Application
(app-of-apps child). Kept intentionally to the two customizations we apply on top of the
stock install — **not** the whole install, so Argo CD never churns its own runtime secret /
session state.

| Resource | Why it's here |
|----------|---------------|
| `cmd-params-cm.yaml` | `server.insecure=true` — TLS terminates at Traefik |
| `server-service.yaml` | `argocd-server` as NodePort, http pinned **30080** (Traefik target) |

The `argocd-config` Application uses `prune: false` (never delete control-plane resources) +
`selfHeal: true` (keep these two applied) + `ServerSideApply=true` (safe shared field ownership).

## Base install (pinned) — for a full rebuild

The stock install is applied out-of-band (Argo CD can't bootstrap itself). Pinned to the running
version so a rebuild is deterministic:

```bash
# Argo CD v3.4.5 — MUST use server-side apply (ApplicationSet CRD exceeds the client-side limit)
kubectl create namespace argocd
kubectl apply -n argocd --server-side --force-conflicts \
  -f https://raw.githubusercontent.com/argoproj/argo-cd/v3.4.5/manifests/install.yaml
# then apply the app-of-apps root (bootstrap/root.yaml); Argo CD takes over the config above.
```

### Post-install: repo-server DNS fix (required for external Helm charts)

After the base install, apply the repo-server `ndots:1` patch — without it, `helm pull` of external
charts (Vault, ESO, Crossplane #33) resolves `<host>.example.com` → Traefik and fails TLS
(EVOLUTION #34):

```bash
kubectl -n argocd patch deploy argocd-repo-server \
  --patch-file platform/argocd/repo-server-dns-patch.yaml
```

Not folded into the `argocd-config` kustomize because it targets a resource from the out-of-band
base install (SSA field-ownership conflict). See `repo-server-dns-patch.yaml` for the full rationale.
