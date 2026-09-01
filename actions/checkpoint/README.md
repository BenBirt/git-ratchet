# git-ratchet checkpoint action

A composite GitHub Action that runs the full origin-side checkpoint lifecycle:
records the ref in the transparency log, submits the log's new head to the
policy's witnesses, collects cosignatures, evaluates quorum, stores the result
and pushes it.

## How it works

1. Checks out the repository with full history (`fetch-depth: 0`).
2. Installs git-ratchet via the [`setup`](../setup) action.
3. Fetches `refs/ratchet/log`, which does not exist on a first run.
4. Records the ref in the log (`git-ratchet log --ref`).
5. **Pushes the log entry.**
6. Checkpoints the log (`git-ratchet checkpoint`), which collects
   cosignatures and stores the result.
7. Pushes the checkpoint.

Steps 5 and 7 are separate on purpose. The entry recorded in step 4 is the
durable record of where the ref pointed, and pushing it before anyone is asked
to cosign means a witness that is down, slow, or refusing cannot cost the
repository that record. The next run's checkpoint covers whatever the log holds
by then, so an entry left uncheckpointed is not an entry lost.

Neither push is forced. Each log commit is parented on the one before, so an
ordinary push rejects a rewritten log before any git-ratchet code runs — a
check worth keeping rather than overriding.

## Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `ref` | Yes | — | Full ref path to checkpoint (e.g. `refs/heads/main`). |
| `origin-key` | Yes | — | Origin private key file contents, as written by `genkey`. |
| `policy` | Yes | — | Path to the witness policy file (relative to repo root). |
| `github-token` | No | `github.token` | Token that can open issues on witness repositories, for `github-issue://` witnesses. |
| `version` | No | `latest` | git-ratchet version to install. |
| `timeout` | No | `300` | Seconds to wait for each witness to cosign. |

## Permissions

The workflow must grant:

```yaml
permissions:
  contents: write   # push refs/ratchet/log
```

## Usage

```yaml
on:
  push:
    branches: [main]
    tags: ['v*']

jobs:
  checkpoint:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: project-oak/git-ratchet/actions/checkpoint@main
        with:
          ref: ${{ github.ref }}
          origin-key: ${{ secrets.ORIGIN_KEY }}
          policy: ratchet-checkpoint.policy
```

Reaching a `github-issue://` witness needs a token that can create issues on
the witness repository:

```yaml
          github-token: ${{ secrets.WITNESS_GITHUB_TOKEN }}
```
