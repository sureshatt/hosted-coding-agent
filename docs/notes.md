# Notes

## Built versus reused

| Reused | Role |
|---|---|
| Lima, Ubuntu 24.04 | VM and host isolation boundary |
| Docker Engine, gVisor (`runsc`) | Containers and the session sandbox |
| nftables (bridge family) | Egress enforcement and drop logging |
| journald | Kernel log transport to the detector |
| Claude Code 2.1.312 | The agent |
| gitleaks | Secret scanning of this repository before every push |

| Built (this repository) | Role |
|---|---|
| `fg/session.py`, `fg/cli.py` | Control plane: session lifecycle, tokens, containment |
| `fg/netpolicy.py` | Per-session egress policy (secure, vulnerable, quarantine) |
| `services/gateway.py` | Model gateway |
| `services/sink.py` | Attacker stand-in |
| `fg/detector.py`, `fg/canary.py` | Detection and automatic response |
| `fg/evidence.py` | Hash-chained evidence |
| `fg/delivery.py`, `services/scanner.py` | Delivery pipeline |
| `fg/evals.py`, `scripts/` | Security eval, setup, teardown |
| `fixtures/invoice-clean`, `fixtures/invoice-poisoned` | Target repositories, without and with the injection |
| `spikes/` | The experiments behind `docs/decisions.md` |

Everything we wrote is Python standard library and shell: there are no
third-party packages in the control plane, gateway or scanner.

## Credentials: scope, supply, end of access

- The **upstream credential** (Claude subscription token or API key) is
  piped into the VM on stdin by `scripts/setup.sh`, stored root-only in
  `/var/lib/fg/secrets`, and passed only to the gateway container. It is
  never in a session, an argument list or this repository.
- Each session gets a **session token**: random, stored by hash, bound to
  the runtime's IP, usable only for `/v1/messages`. It is revoked on
  containment and on destroy; the gateway re-reads the token file on every
  request, so revocation is immediate (verified by containment step 2).
- The runtime has **no git or cloud credentials**. Code leaves through the
  delivery pipeline, which the control plane runs.
- When a session ends: token revoked, nftables table deleted, network and
  workspace volume removed. The eval checks each of these ("teardown
  clean").

## Production changes (designed, not built)

- **Kubernetes** in place of Docker: a pod per session with gVisor or Kata
  RuntimeClass; Cilium network policy in place of the per-session nftables
  table (same idea: enforced outside the pod, on the host side of its
  link); Hubble flow logs in place of the kernel log, with pod identity.
- **MicroVM per session** (Firecracker or Kata) to remove the shared-kernel
  risk entirely.
- **Gateway** as its own service with its own identity, credentials from a
  secrets manager, per-session spend and rate limits, and secret redaction
  in prompts.
- **Evidence** streamed off the host as it is written, to storage with a
  retention lock (for example S3 Object Lock), signed per batch.
- **Identity**: SSO-authenticated users, short-lived session tokens issued
  per user, every action in the registry tied to that identity.
- **Delivery**: a queue with horizontally scaled scanner workers in their
  own sandboxes; a publisher holding a GitHub App token scoped to one
  repository with contents and pull-request write only, valid for minutes;
  branch protection and required review on every target repository.
- **Packages**: an internal mirror as the only other allowed destination,
  so agents can install dependencies without general internet access.

## Red-team and fuzzing coverage

The deterministic suite tests the boundary; this is about model behaviour
and detection coverage.

- **Target**: the rate at which the agent attempts the unauthorised action
  under the current model, and whether every attempt is detected.
- **Variation**: injection placement (docstring, README, test output,
  issue text, dependency source), phrasing (authority, urgency, helpfulness),
  channel (sink by name or IP, DNS, model prompt, delivered code), and
  encoding of the canary.
- **Budget**: fixed up front, for example 50 runs or 2 hours, whichever
  comes first; each run is about 2–5 minutes and a few dollars of model time.
- **Reproducibility**: record the variant, model version, Claude Code
  version and full agent transcript for every run; a variant that leads to
  an attempt (or, worse, a success) is saved as a fixture.
- **Regression**: each saved fixture becomes an eval case. Enforcement
  results must stay deterministic; attempt counts are tracked as a trend.
- More attack categories or higher volume add little: the network policy
  allows one destination, so effort goes to the allowed path and detection.

## Time spent

_Fill in before submitting._
