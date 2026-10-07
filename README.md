# homelab-platform

The GitOps source of a small Kubernetes platform: a single-node k3s cluster on a home
hypervisor, laid out and operated the way a production one would be. Argo CD applies
everything here; nothing is `kubectl apply`'d by hand after the one-line bootstrap.

It is a homelab, so it is one node and modest resource limits. The interesting part is not the
size but the decisions: how secrets get in without a credential stored anywhere, what gets
backed up and how a restore is known to work, and how the pipeline is kept from lying.

## What is in it

| Layer | What | How it is deployed |
|---|---|---|
| GitOps | Argo CD v3.4.5, app-of-apps, self-managed config | `bootstrap/root.yaml` → `applications/` |
| Secrets | HashiCorp Vault 1.21 (integrated Raft, TLS listener) + External Secrets Operator 2.8 | Helm charts, values vendored in `platform/` |
| Backup | Daily Vault Raft snapshots, `age`-encrypted, shipped off-site and to nearline storage; Velero 1.18 file-system backups of every volume to S3-compatible storage | `platform/vault-backup/`, `platform/velero/` |
| Observability | kube-prometheus-stack (metrics), Loki + Alloy (logs), Tempo + OpenTelemetry Collector (traces), one Grafana over all three | `platform/monitoring/`, `platform/logging/`, `platform/tracing/` |
| CI runners | GitLab Runner on the Kubernetes executor: non-root job pods, namespaced least-privilege RBAC, two releases from one values file | `platform/gitlab-runner*/` |
| Agent access | A read-only ServiceAccount for an AI coding agent: `view` plus a short list of cluster-scoped reads, no Secrets, no `exec` | `platform/mcp-readonly/` |
| Workloads | podinfo (the GitOps demo, traced and scraped), Ollama (CPU-only local inference) | `apps/` |

## Layout

```text
bootstrap/root.yaml      the app-of-apps root - applied once, by hand
applications/            one Argo CD Application per managed thing; the root watches this folder
platform/<name>/         platform services: vendored Helm values, or a kustomize root
platform/<name>-config/  what a chart needs to exist first (an ExternalSecret, a store)
apps/<name>/             workloads, plain manifests
ci/                      the pipeline's scripts and its planted-defect fixtures
```

A chart-based service is a multi-source Application: the upstream chart pinned to an exact
version, plus a values file from this repository, so every value is reviewed in a diff.

### Sync order

| Wave | Applications | Why there |
|---|---|---|
| 0 | `argocd-config`, `mcp-readonly`, `podinfo`, `ollama` | no dependency on secrets |
| 1 | `vault` | the backend comes first |
| 2 | `external-secrets` | the operator and its CRDs |
| 3 | `external-secrets-config`, `monitoring-config`, `velero-config`, `gitlab-runner-config`, `gitlab-runner-portfolio-config` | the store, then each consumer's `ExternalSecret` |
| 4 | `monitoring`, `logging`, `tracing`, `velero`, `vault-backup`, `gitlab-runner`, `gitlab-runner-portfolio` | charts whose `existingSecret` must already resolve |

## Decisions worth reading

**No standing credential for secrets.** External Secrets logs in to Vault with its own
ServiceAccount token through Vault's Kubernetes auth method; the Vault role pins the token
audience, and the policy lists each consumer's path explicitly. Git holds references only.
See [`clustersecretstore.yaml`](platform/external-secrets-config/clustersecretstore.yaml).

**A backup is a restore that has been run.** The Vault backup takes an application-consistent
Raft snapshot, encrypts it to a recipient whose private key is not in the cluster, and never
writes the plaintext to disk (`emptyDir` in memory). The identity that takes it can read the
snapshot endpoint and nothing else. Recovery needs two things kept in separate places - the
encrypted file and the offline key. Both this path and the Velero path have been restored for
real, not just scheduled. See [`platform/vault-backup/`](platform/vault-backup/README.md).

**The `ndots` trap.** With a wildcard DNS record on the cluster's search domain, an external
name such as a Helm chart host resolves to the ingress instead of the internet, and fails with
a TLS error that points nowhere near DNS. The fix (`ndots:1`, or a trailing dot) appears in
three places here, each with the reasoning beside it:
[`repo-server-dns-patch.yaml`](platform/argocd/repo-server-dns-patch.yaml) is the best starting
point.

**One values file, two releases.** The two GitLab runners load the same values file, so their
job-pod security posture cannot drift apart; the second adds one override. The comments in
[`platform/gitlab-runner/values.yaml`](platform/gitlab-runner/values.yaml) record how a comment
in the wrong place would have restarted the first runner.

**Never prune what holds state or access.** `vault`, `argocd-config` and `mcp-readonly` sync
with `prune: false`; everything else prunes and self-heals.

## The pipeline

Every job is fail-closed, and every job first runs its own tool against a planted defect and
must see the expected finding before it looks at the repository
([`ci/expect-fail.sh`](ci/expect-fail.sh), [`ci/fixtures/negative/`](ci/fixtures/negative/README.md)).
A tool that is missing, or a check that has gone quiet, turns the pipeline red instead of green.

| Job | Checks |
|---|---|
| `release_gate` | nothing identifying in any commit (see below) |
| `gitleaks` | no secret in any commit |
| `yamllint` | parser-level defects, duplicate keys |
| `manifests_kubeconform` | every Application, kustomize root and plain directory, rendered as Argo CD would and validated against the Kubernetes and CRD schemas; an unknown kind fails |
| `helm_kubeconform` | every pinned chart rendered with its vendored values, then the same validation |

[`ci/render-apps.sh`](ci/render-apps.sh) is driven by the Application files themselves, so a new
Application is covered without touching the pipeline.

## How this repository is published

This is a curated copy of a private working repository, not a mirror of it.

- **Allowlist in.** A file is here because an export list names it, one line per file.
  Everything else stays private by default.
- **A net under the allowlist.** [`ci/public_lint.py`](ci/public_lint.py) reads every commit -
  file contents, file names, commit messages, author and committer - and fails on anything that
  identifies a network, a person, a company or a place.
- **A human merge.** Every change arrives by merge request, and a merge request cannot merge on
  a red pipeline.

### What was changed on the way out

The manifests are the real ones with identifying values replaced. That makes this a reference
to read, not something to apply unchanged:

| In the private repository | Here |
|---|---|
| the DNS domain | `example.com` |
| LAN addresses | `192.0.2.x` (the documentation range of RFC 5737) |
| the Git server address in every `repoURL` | this repository's own address |
| the Vault CA certificate, the backup encryption recipient, pinned SSH host keys | `REPLACE-...` placeholders |
| virtual machine numbers | the machine's role ("the k3s node", "the Docker host") |
| the time zone of the schedules | `Etc/UTC` |
| the off-site storage provider | "external cloud storage" - any object store or drive service an `rclone` remote can reach |

### Reading the comments

Comments cite the private repository's records, and they are left in because each one marks a
decision that had a tracked reason: `ev-114` or `EVOLUTION #89` is a change proposal, `bl-027` a
backlog item, `td_vault_001` a technical-debt entry, `s59` a working session. Paths such as
`services/vault/docs/...` point into the private operations repository, where the runbooks live.

## Licence

Code and configuration: [Apache-2.0](LICENSE). Documentation (this file and the other `*.md`
files): [CC BY 4.0](LICENSE-docs).
