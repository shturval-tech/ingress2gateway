# Shturval soft-fork of ingress2gateway

## Remotes and branches

| Remote / branch | Role |
|-----------------|------|
| `upstream` → `github.com/kubernetes-sigs/ingress2gateway` | Upstream source of truth |
| `origin` → `github.com/shturval-tech/ingress2gateway` | Soft-fork |
| `main` | Fast-forward / merge only from `upstream/main` |
| `shturval` | Product branch: `main` + `shturval/` + selected contrib patches |
| `contrib/<topic>` | One upstreamable topic; cherry-pick into `shturval` and open upstream PR |

## Sync rules

1. `git fetch upstream && git checkout main && git merge --ff-only upstream/main`
2. `git checkout shturval && git merge main` (expect conflicts only under `shturval/` or contrib files)
3. Upstream PRs contain **only** commits from `contrib/*`, rebased onto `upstream/main`
4. Never put Shturval product names, labels, or `gitlab.jet.su` into `contrib/*` commits

## Public build — no gitlab.jet.su

Anyone must build from public sources after cloning this GitHub repo:

```bash
git clone https://github.com/shturval-tech/ingress2gateway
cd ingress2gateway
git checkout shturval
go build -o ingress-gw-migrate ./shturval/cmd/ingress-gw-migrate
# or: make shturval-build
```

- Module path stays `github.com/kubernetes-sigs/ingress2gateway` so contrib commits stay clean for upstream.
- `go install github.com/shturval-tech/ingress2gateway/shturval/cmd/...@latest` is **not** supported.
- Do **not** `require` / `replace` / `import` anything from `gitlab.jet.su`.
- CI dependency guard scans Go/module/workflow files (not docs that must mention the ban).

## Layout

- `pkg/i2gw/...` — upstream tree; touch only on `contrib/*`
- `shturval/` — product overlay (never for upstream PRs)

## Plan 5

This CLI does **not** own platform Helm routes or ClusterConfig cutover. Platform brownfield migration stays in cluster-manager.

## Upstream PR drafts (contrib)

Open against `kubernetes-sigs/ingress2gateway` (requires fork permissions / `gh`):

1. Gateway API bump: https://github.com/kubernetes-sigs/ingress2gateway/compare/main...shturval-tech:ingress2gateway:contrib/gateway-api-1.6.1?expand=1
2. Shared Gateway helpers (includes bump): https://github.com/kubernetes-sigs/ingress2gateway/compare/main...shturval-tech:ingress2gateway:contrib/shared-gateway?expand=1

Branches are published on `origin` (`shturval-tech/ingress2gateway`). Diffs contain **no** `shturval/` paths.
