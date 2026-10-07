# homelab-platform

A Kubernetes platform run the GitOps way on a single-node k3s cluster, laid out as a production
one would be: Argo CD app-of-apps, secrets projected from Vault, metrics, logs and traces,
scheduled backups with a restore that has actually been drilled, and a CI pipeline in which
every check first proves that it can fail.

> **Status: being published in stages.** The first commit is the release gate and its pipeline
> job. The platform layout follows through merge requests, and this page grows with it.

## How this repository is published

This is a curated copy of a private working repository, not a mirror of it.

- **Allowlist in.** A file is here because an export list names it, one line per file.
  Everything else stays private by default.
- **A net under the allowlist.** [`ci/public_lint.py`](ci/public_lint.py) reads every commit —
  file contents, file names, commit messages, author and committer — and fails on anything that
  identifies a network, a person, a company or a place. Addresses in examples come from the
  documentation ranges of RFC 5737.
- **A gate that proves itself.** The pipeline job runs the check against a planted defect
  before it scans the repository ([`ci/expect-fail.sh`](ci/expect-fail.sh)), on every run.
- **A human merge.** Every change arrives by merge request, and a merge request cannot merge on
  a red pipeline.

## Licence

[Apache-2.0](LICENSE).
