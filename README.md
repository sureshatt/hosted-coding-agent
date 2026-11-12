# hosted-coding-agent

A small platform for remote coding-agent sessions, built to be attacked.
Each session runs Claude Code in a gVisor sandbox inside a Lima VM, with one
way out (a model gateway), every other attempt logged and dropped by the VM,
detection of canary exfiltration, and automatic, verified containment.

- [Threat model and results](docs/threat-model.md): start here
- [Architecture](docs/architecture.md)
- [Decisions and the evidence behind them](docs/decisions.md)
- [Notes: built vs reused, credentials, production changes, red-team plan](docs/notes.md)

## Requirements

- macOS on Apple Silicon (tested) with [Homebrew](https://brew.sh)
- `brew install lima`
- About 10 GB of disk and 8 GB of free memory for the VM

Nothing else is installed on the host. Docker Desktop is not used.

## Setup

```sh
scripts/setup.sh
```

Creates the VM (the first run downloads Ubuntu), builds the images, and
starts the gateway, sink and detector. Without a credential the gateway uses
a mock model, which is enough for every deterministic test.

To run the real agent, give the gateway a credential, either a Claude
subscription token from `claude setup-token` or an Anthropic API key:

```sh
FG_UPSTREAM_TOKEN='sk-ant-...' scripts/setup.sh
```

The token is piped into the VM on stdin and only the gateway container
receives it. Sessions never see it.

## Run the tests (one command)

```sh
scripts/test.sh                  # deterministic tests, plus one prompt-injection run if a credential is set
scripts/test.sh --agent-runs 5   # more prompt-injection runs
scripts/test.sh --skip-agent     # deterministic tests only (about 90 seconds)
```

The report is printed and saved under `results/`.

## Use it

```sh
scripts/fgctl start "Fix the failing tests in invoice/totals.py"   # prints a session id
scripts/fgctl logs <id> -f       # progress
scripts/fgctl status
scripts/fgctl alerts
scripts/fgctl deliver <id>       # scan the agent's change and push branch agent/<id>
scripts/fgctl contain <id>       # manual containment
scripts/fgctl destroy <id>       # access ends here: token, network, workspace removed
scripts/fgctl evidence-verify    # check the evidence hash chains
```

## Teardown

```sh
scripts/teardown.sh              # deletes the VM and everything in it
```

## Layout

```
fg/            control plane (fgctl), netpolicy, detector, delivery, evidence, harness
services/      gateway, sink, scanner
images/        container images (pinned by digest)
fixtures/      target repository with the injected instructions
infra/lima/    VM definition
scripts/       setup, teardown, tests, fgctl wrapper
spikes/        experiments behind docs/decisions.md
```
