# Vault (platform) — EVOLUTION #34

HashiCorp Vault (OSS, BUSL) as the **backend** for the External Secrets Operator. Deployed by the
`vault` Argo CD Application (`applications/vault.yaml`) — upstream Helm chart `hashicorp/vault`
**0.32.0** (app **v1.21.2**) + the vendored `values.yaml` here.

- **Storage:** integrated Raft on a k3s local-path PVC (single-node today; HA/2nd-node → bl-027).
- **Exposure:** UI/API on NodePort **30820** → Traefik file route `vault.example.com`
  (websecure, wildcard cert, ipAllowList `192.0.2.0/24`). TLS terminates at Traefik; the
  in-cluster listener runs `tls_disable` (same trust model as argocd/rancher — LAN-only). Backend
  TLS is future hardening (`td_vault_001` in the service STATE.yaml).
- **Injector:** disabled — secrets reach workloads via ESO, not the Vault Agent Injector.

## Operational reality (this is the point of running it properly)

Vault comes up **sealed** after every restart. A freshly-synced pod is `Running` but **0/1 Ready**
until unsealed — that is expected, not a failure.

- **Init once:** `vault operator init` → 5 unseal keys + root token → **offline custody, never git**.
- **Unseal:** Shamir (interim). Transit auto-unseal is the target once a 2nd Vault/HA node exists
  (bl-027) — one Vault cannot auto-unseal itself.
- **Backup:** `vault operator raft snapshot save` off-box; test restore.

Full runbook: `services/vault/docs/QUICKSTART.md` in the private operations repository.

## Auth for ESO

Kubernetes auth method — ESO's ServiceAccount maps to a least-privilege Vault role/policy scoped to
the KV paths ESO reads. No standing credential is stored (the SA JWT is the identity). The
`ClusterSecretStore` that wires this is added in Stage D once the auth method is configured.
