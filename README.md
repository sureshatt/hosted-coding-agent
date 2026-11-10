# hosted-coding-agent

A small platform for remote coding agent sessions, built to be attacked:
disposable sessions, an egress boundary the agent cannot change, detection of
canary exfiltration, and containment.

> Status: work in progress. The VM and the session network boundary are in
> place; the control plane, gateway, detector and test harness are next.

## Requirements

- macOS on Apple Silicon or Intel, with [Homebrew](https://brew.sh)
- `brew install lima`

Everything else runs inside a Lima VM created by the scripts. Docker Desktop
is not used.

## Quick start

```sh
scripts/vm.sh up                                   # create the VM (first run downloads Ubuntu)
scripts/vm.sh shell sudo spikes/netns-gvisor/run.sh  # check the session network boundary
scripts/vm.sh down                                 # delete the VM and everything in it
```

## Docs

- [Architecture](docs/architecture.md)
- [Decisions and evidence](docs/decisions.md)
