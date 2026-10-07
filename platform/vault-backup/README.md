# vault-backup — scheduled Vault Raft snapshots (EVOLUTION #43)

Daily, application-consistent Raft snapshots of the in-cluster Vault, **age-encrypted before they
leave the cluster**, shipped to external cloud storage (authoritative off-site) and the Proxmox ZFS pool
(nearline, fast restore). Closes `td_vault_002`.

## Why this exists

Vault is tier-1 — it holds every secret ESO projects — and stored its only copy on a single Raft
replica backed by a node-local `local-path` PVC on the k3s node. Everything in this homelab also runs on
**one** Proxmox host (`bl-028`), so any on-host backup target dies with the host. The backup has to
leave the machine entirely.

## Shape

```
CronJob (03:17 Etc/UTC, Forbid concurrency)
  initContainer  snapshot   hashicorp/vault:1.21.2   k8s-auth -> vault operator raft snapshot save
  container      ship       alpine:3.22              age encrypt -> rclone -> offsite + pmxzfs
```

- **Identity**: the `vault-backup` ServiceAccount JWT is exchanged at Vault's Kubernetes auth
  endpoint for the `vault-backup` role → `vault-snapshot` policy (`read` on
  `sys/storage/raft/snapshot` and nothing else). **Never the root token.**
- **Encryption**: `age`, to a *dedicated* recipient minted for backups only. The private half is in
  offline operator custody — not in this cluster, not in this repo, not in the cloud storage account.
- **`/work` is `emptyDir{medium: Memory}`**, so the plaintext snapshot never touches node disk, and
  it is `rm`'d the moment encryption succeeds.
- **Retention**: 7 daily + 4 weekly (Sunday runs are promoted into `weekly/`).

## The two halves of a recovery

A snapshot alone restores nothing. You need **both**:

1. the `.age` artifact (cloud storage or ZFS), and
2. the offline **age private key** — and then the offline **Vault unseal keys**.

They are deliberately kept in separate trust domains, so compromise of the cloud storage account yields
ciphertext and nothing more.

## Credentials

`rclone.conf` (cloud storage credential + Proxmox sftp key) is **not in git**. It lives in Vault at
`secret/platform/vault-backup` and is projected by the `vault-backup-rclone` ExternalSecret. See
`services/vault/docs/BACKUP_DR.md` in the private operations repository for the bootstrap and the tested
restore runbook.

## DNS gotcha

The pod sets `ndots:1`. Without it, CoreDNS `ndots:5` + the `example.com` search domain +
the `*.example.com` → Traefik wildcard make every external hostname resolve to `192.0.2.20`.
Same class of fix as the `argocd-repo-server` patch from #34.
