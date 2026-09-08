# ingress-gw-migrate (Shturval overlay)

Ops CLI for migrating client Ingress resources to Gateway API under Cilium, with optional **coexistence** mode that keeps selected hostnames on ingress-nginx via per-host TLS passthrough.

This tool is **not** Plan 5: it does not patch ClusterConfig, platform Helm routes, or VIP cutover owned by cluster-manager.

## Build from source (public; no gitlab.jet.su)

```bash
git clone https://github.com/shturval-tech/ingress2gateway
cd ingress2gateway
git checkout shturval
export GOTOOLCHAIN=go1.26.0
make shturval-build
# binary: ./ingress-gw-migrate
```

Dependencies are public only (`github.com/kubernetes-sigs/ingress2gateway`, `k8s.io/*`, `sigs.k8s.io/gateway-api`, etc.). Do **not** add `require`/`replace`/`import` from `gitlab.jet.su`.

`go install github.com/shturval-tech/ingress2gateway/shturval/cmd/...@latest` is **not** supported (module path stays upstream for contrib hygiene).

## Modes

| Mode | Purpose |
|------|---------|
| `convert` (default) | Move selected Ingress hostnames to Gateway-owned HTTPRoute/TLSRoute + listeners |
| `coexist` | Gateway fronts VIP; retained HTTPS hosts use **per-host** TLS passthrough to nginx; HTTP uses catch-all `:80` → nginx |

Coexist never emits catch-all TLS `:443` (measured `ProtocolConflict` with per-host HTTPS listeners). Unknown SNI without a matching listener resets the connection (no default cert).

## Commands

```bash
ingress-gw-migrate preflight  --input-file ingress.yaml --providers ingress-nginx
ingress-gw-migrate print      --input-file ingress.yaml --providers ingress-nginx --output-dir ./out
ingress-gw-migrate convert    # preflight + print; exit 2 on blockers
ingress-gw-migrate verify       # read-only cluster checks (stub offline)
```

Exit codes: `0` success (warnings OK), `1` input/operational error, `2` preflight blockers.

## Apply order

When using `--split=infra,app` (default):

1. Apply `out/infra/` (Gateway, listeners, retained nginx routes, ReferenceGrants, BackendTLSPolicy)
2. Wait for Gateway Programmed; confirm no listener `ProtocolConflict`
3. Apply `out/app/` (HTTPRoute/TLSRoute/Certificate for gateway-owned workloads)
4. Run `verify` against the cluster

## Configuration flags (high level)

- `--mode=convert|coexist`
- `--gateway-name`, `--gateway-namespace`, `--gateway-class-name`, `--default-tls-secret`
- `--nginx-service`, `--nginx-namespace`, `--coexist-https=passthrough|reencrypt`
- `--own-host`, `--retain-host`, `--max-passthrough-listeners` (default 32)
- `--emit-certificates`, `--split=infra,app|none`, `--force`, `--check-shturval-crds`

See `ingress-gw-migrate --help` for the full list.

## Golden tests

```bash
export GOTOOLCHAIN=go1.26.0
make shturval-test
UPDATE_GOLDEN=1 make shturval-test   # refresh golden files when output intentionally changes
```

Fixtures live under `shturval/testdata/<case>/`.

## Soft-check Shturval CRDs

`--check-shturval-crds` (default **off**) optionally looks up known GVK via dynamic/unstructured clients (`ClusterConfig`, `ShturvalServiceConfig`). Missing CRD / NotFound / Forbidden → **skip**, never a private Go module import. Plan 5 still owns writing ClusterConfig.

## Soft-check / private GitLab

This repository must stay buildable without VPN. CI fails if `gitlab.jet.su` appears in Go modules, sources, Makefile, goreleaser, or workflows.

## Sync with upstream

See [FORK.md](./FORK.md) for branch layout (`main`, `shturval`, `contrib/*`) and contribution rules.
