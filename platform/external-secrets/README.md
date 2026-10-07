# External Secrets Operator (platform) — EVOLUTION #34

The repo-wide **git-layer secrets interface**. Deployed by the `external-secrets` Argo CD
Application (`applications/external-secrets.yaml`) — upstream Helm chart
`external-secrets/external-secrets` **2.8.0**.

Git holds only an `ExternalSecret` (a *reference*); ESO reads the value from the in-cluster Vault
backend and projects it into a native k8s `Secret` with a refresh TTL. **No plaintext in git, ever.**

## Wiring (Stage D)

Once Vault has its Kubernetes auth method + ESO policy/role configured, a `ClusterSecretStore` of
type `vault` (auth: Kubernetes, ESO ServiceAccount → Vault role) is committed here. Consumers then
declare `ExternalSecret` resources referencing that store.

The standard, path conventions, and the "how to add a secret" runbook live in the
private operations repository: `context/SECRETS_STANDARD.yaml` + `docs/SECRETS_MANAGEMENT.md`.
