# Downstream release branch

Read when building this fork or merging a new upstream release.

`codex/svj-v0.21.3` starts at upstream `v2026.9.14` (Hermes 0.21.3).
The fork keeps separate commits for Codex OAuth recovery, direct Cloudflare
Access dashboard authentication, and WhatsApp group/direct-message filtering.
Deployment configuration and runtime data belong outside this public repository.

Build a clean, reviewed commit that has been pushed to the fork:

```sh
test -z "$(git status --porcelain)"
revision=$(git rev-parse HEAD)
docker build -f Dockerfile.downstream --build-arg FORK_REVISION="$revision" \
  -t "hermes-downstream:$revision" .
```

The image carries the exact commit in its OCI revision label and
`/opt/hermes/.fork-revision`. The official pinned base supplies dependencies;
the fork supplies application source and the rebuilt dashboard. When updating
upstream, update the base digest with the upstream dependency lockfiles, inspect
removed/moved files against the base, and rerun the focused tests before changing
the deployed image. Deploy an exact commit, never a floating branch tag.

```sh
scripts/run_tests.sh tests/agent/test_pool_only_codex_refresh.py \
  tests/hermes_cli/test_cloudflare_access_direct.py
node --test scripts/whatsapp-bridge/incoming_policy.test.mjs \
  scripts/whatsapp-bridge/allowlist.test.mjs
```

The dashboard and messaging gateway can use the same image with separate launch
commands and shared persistent data. The bridge must run from this image's
`scripts/whatsapp-bridge` source; an older writable copy in the data directory is
not automatically updated. Preserve WhatsApp pairing data when updating it.

OAuth access-token expiry is normal. The recovery fix adopts only tokens belonging
to the same persistent credential row and rejects a different row, including one
selected concurrently. An actually revoked refresh token still needs reauthentication.
