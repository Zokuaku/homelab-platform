#!/usr/bin/env bash
# ci/render-apps.sh — render what Argo CD would apply, so kubeconform can validate it.
# EVOLUTION ev-114 sitting 2 (bl-016 Phase A). Driven by the Application files themselves:
# a new applications/<name>.yaml is covered without editing CI.
#
#   render-apps.sh manifests   -> Application objects (applications/ + bootstrap/), every
#                                 kustomize root (kustomize build) and every plain-directory
#                                 source (the files Argo applies in directory mode)
#   render-apps.sh helm        -> every chart source of every multi-source Application:
#                                 helm template <chart>@<targetRevision> with the vendored
#                                 values file ($values/... resolves to this repo)
#
# Output: $OUT/<mode>/<app>[-<chart>].yaml — one file per source. Exit non-zero on the first
# source that fails to render (a broken kustomization or an unrenderable chart is itself a
# validation failure). Tools: yq (mikefarah v4), kustomize, helm — all in alpine/k8s.
# Non-root safe: writes only under $OUT and $HOME (helm's cache) — HOME=/builds in CI.
# APPS_DIR (default applications): where the Application files are read from. The CI self-tests
# (ev-115) point it at ci/fixtures/negative/render/applications — planted Applications that
# must make THIS script exit non-zero, in each mode.
set -euo pipefail

MODE="${1:?usage: render-apps.sh manifests|helm}"
OUT="${OUT:-rendered}/$MODE"
KUBE_VERSION="${KUBE_VERSION:-1.36.0}"
# API versions Argo CD would report from THIS cluster: charts gate ServiceMonitor/PrometheusRule
# templates on them (Capabilities.APIVersions.Has). Keep in step with what the cluster serves.
API_VERSIONS=(monitoring.coreos.com/v1 external-secrets.io/v1 external-secrets.io/v1beta1)

rm -rf "$OUT"
mkdir -p "$OUT"
failed=0

# Concatenate files as separate YAML documents. A bare cat merges two files that lack a
# leading '---' into ONE document and kubeconform reports 'key "apiVersion" already set'
# (first local run, s59) — the separator is what Argo's directory mode implies.
cat_docs() {
  for f in "$@"; do
    printf -- '---\n'
    cat "$f"
    printf '\n'
  done
}

# retry <attempts> <command...>: for network fetches only (chart index + chart download).
# Backs off 5 s, 10 s between attempts; a real chart error just fails three times quickly.
retry() {
  local attempts="$1" i
  shift
  for i in $(seq 1 "$attempts"); do
    if "$@"; then return 0; fi
    echo "attempt $i/$attempts failed: $1 ${2:-}" >&2
    [ "$i" -lt "$attempts" ] && sleep $((i * 5))
  done
  return 1
}

APPS_DIR="${APPS_DIR:-applications}"
app_files=("$APPS_DIR"/*.yaml)

case "$MODE" in
  manifests)
    # 1. the Application objects themselves (argoproj.io schema from the CRD catalog)
    cat_docs "$APPS_DIR"/*.yaml bootstrap/*.yaml > "$OUT/_applications.yaml"
    echo "rendered: Application objects -> $OUT/_applications.yaml ($(grep -c '^kind: Application' "$OUT/_applications.yaml") apps)"
    # 2. every path: source (single- or multi-source), skipping $values refs
    for app in "${app_files[@]}"; do
      name="$(yq '.metadata.name' "$app")"
      paths="$(yq '([.spec.source] + (.spec.sources // [])) | map(select(.path != null and .ref == null)) | .[].path' "$app")"
      for p in $paths; do
        target="$OUT/${name}.yaml"
        if [ -f "$p/kustomization.yaml" ] || [ -f "$p/kustomization.yml" ]; then
          if kustomize build "$p" > "$target"; then
            echo "rendered: $name kustomize $p -> $target"
          else
            echo "FAILED:   $name kustomize build $p" >&2; failed=1
          fi
        else
          # directory mode: Argo applies every *.yaml/*.yml in the path (recurse: false by default)
          recurse="$(yq '([.spec.source] + (.spec.sources // [])) | map(select(.path == "'"$p"'")) | .[0].directory.recurse // false' "$app")"
          if [ "$recurse" = "true" ]; then
            mapfile -t files < <(find "$p" -name '*.y*ml' | sort)
          else
            mapfile -t files < <(find "$p" -maxdepth 1 -name '*.y*ml' | sort)
          fi
          cat_docs "${files[@]}" > "$target"
          echo "rendered: $name directory $p -> $target"
        fi
      done
    done
    ;;
  helm)
    api_flags=()
    for v in "${API_VERSIONS[@]}"; do api_flags+=(--api-versions "$v"); done
    # Add every chart repository ONCE (helm caches its index) instead of --repo per chart, which
    # re-downloads each index.yaml per template call. Every network step is retried: the first
    # main run (job 163, s59) died on ONE transient 'context deadline exceeded' fetching the
    # velero index from GitHub Pages while a second pipeline ran the same job concurrently.
    repos="$(for app in "${app_files[@]}"; do yq '(.spec.sources // []) | map(select(.chart != null)) | .[].repoURL' "$app"; done | sort -u)"
    for repo in $repos; do
      alias="$(printf '%s' "$repo" | sed 's#^https\?://##; s#[^A-Za-z0-9]#-#g')"
      if retry 3 helm repo add "$alias" "$repo" --force-update > /dev/null; then
        echo "repo:     $alias = $repo"
      else
        echo "FAILED:   helm repo add $repo (3 attempts)" >&2; exit 1
      fi
    done
    for app in "${app_files[@]}"; do
      name="$(yq '.metadata.name' "$app")"
      ns="$(yq '.spec.destination.namespace' "$app")"
      n="$(yq '(.spec.sources // []) | map(select(.chart != null)) | length' "$app")"
      [ "$n" -gt 0 ] || continue
      for i in $(seq 0 $((n - 1))); do
        src="$(yq "(.spec.sources // []) | map(select(.chart != null)) | .[$i]" "$app")"
        chart="$(yq '.chart' <<< "$src")"
        repo="$(yq '.repoURL' <<< "$src")"
        rev="$(yq '.targetRevision' <<< "$src")"
        release="$(yq ".helm.releaseName // \"$name\"" <<< "$src")"
        vf_flags=()
        for vf in $(yq '.helm.valueFiles // [] | .[]' <<< "$src"); do
          vf_flags+=(-f "${vf#\$values/}")   # $values/<path> = this repo
        done
        target="$OUT/${name}-${chart}.yaml"
        alias="$(printf '%s' "$repo" | sed 's#^https\?://##; s#[^A-Za-z0-9]#-#g')"
        if retry 3 helm template "$release" "$alias/$chart" --version "$rev" --namespace "$ns" \
             --kube-version "$KUBE_VERSION" "${api_flags[@]}" --include-crds "${vf_flags[@]}" > "$target"; then
          echo "rendered: $name helm $chart@$rev -> $target ($(grep -c '^kind:' "$target") objects)"
        else
          echo "FAILED:   $name helm template $chart@$rev" >&2; failed=1
        fi
      done
    done
    ;;
  *)
    echo "usage: render-apps.sh manifests|helm" >&2; exit 2
    ;;
esac

exit "$failed"
