# Negative fixtures — planted defects the CI controls must catch

EVOLUTION ev-115 (bl-016 Phase B residual; the record lives in the private operations
repository). *A control proves itself only through a negative fixture per job*:
every job in `.gitlab-ci.yml` runs its own tool against one of these through
[`ci/expect-fail.sh`](../../expect-fail.sh) before the real scan, on every pipeline. The wrapper
requires a non-zero exit **and** the expected finding in the output, so a missing tool cannot
pass for a catch.

| Job | Fixture | Planted defect | Expected finding |
|---|---|---|---|
| gitleaks | generated in the job (nothing key-shaped is committed) | a fabricated AWS-style key id | `leaks found` |
| yamllint | `yamllint/bad.yaml.fixture` | duplicate mapping key | `key-duplicates` |
| manifests_kubeconform | `render/applications/planted-kustomize.yaml` | kustomization names a missing resource (MR !5, made permanent) | `planted-kustomize kustomize build` |
| manifests_kubeconform + helm_kubeconform | `kubeconform/bad-deployment.yaml.fixture` | string `replicas`, unknown field | `is invalid` |
| manifests_kubeconform | `kubeconform/unknown-kind.yaml.fixture` | a kind with no schema | `could not find schema` |
| helm_kubeconform | `render/applications/planted-helm.yaml` | a chart version that was never published | `planted-helm helm template` |

Rules for this directory:

- **Nothing here is ever applied.** Argo CD sources are `applications/`, `platform/`, `apps/` —
  never `ci/`. The render fixtures are read only when `APPS_DIR` points `ci/render-apps.sh` here.
- **The `.fixture` suffix is deliberate** where the file is *invalid on purpose*: yamllint walks
  the whole tree by extension, and excluding a path from the real scan is itself a way for a
  control to go quiet. The render fixtures are valid YAML and keep `.yaml`.
- **kubeconform skips an explicitly named file that is not `.yaml`/`.yml`/`.json`** — it reports
  `0 resource found` and exits 0. The first local run of the self-test caught exactly that (a
  green control that had validated nothing), so the job copies the kubeconform fixtures to
  `/builds/selftest-kubeconform/*.yaml`, outside the checkout, before validating them.
- **Never commit anything key-shaped.** The gitleaks fixture is assembled in the job from two
  halves that match no rule on their own.
- `ci/expect-fail.sh` is a copy of the estate repo's — change both together.
- A new job lands with its fixture in the same MR.
