# Architecture

```
macOS
└─ Lima VM (Ubuntu · Docker Engine · gVisor · nftables)
   │
   ├─ TRUSTED: processes on the VM, not in containers
   │   fgctl (control plane)  sessions · registry · tokens · containment
   │   detector               reads logs → alerts → automatic containment
   │   scanner                nobody · no network · untrusted export in, verdict out
   │   publisher              pushes only a passing verdict whose hash matches the export
   │   evidence/              append-only, hash-chained · never mounted into containers
   │   git-remote/            bare repo standing in for GitHub
   │
   ├─ nftables, one table per session (bridge family): allow runtime → gateway:8443,
   │   log and drop everything else from the runtime, including traffic to the VM
   │
   ├─ PER SESSION: Docker bridge br-fg-<id>, 10.250.<n>.0/24, NAT off
   │   runtime-<id> (gVisor) .10   Claude Code · uid 1000 · no capabilities · read-only root
   │                               /workspace volume · canary in .env · session token only
   │
   └─ SHARED (runc, hardened; attached to every session bridge)
       model gateway  .2 on each bridge, default route via fg-egress → Anthropic (or mock)
                      reads tokens.json from a read-only mount (revocation)
       exfil sink     .3 on each bridge; reachable at the network level,
                      kept away only by the session's nftables table
```

## Containers

| Container | Lifetime | Role |
|---|---|---|
| agent runtime | per session | Runs the agent on the workspace. Untrusted. |
| model gateway | shared | The only allowed destination. Swaps the session token for the real credential, allows only `POST /v1/messages`, strips server-side tools, scans for the canary, revokes sessions. |
| exfil sink | shared | Stands in for an attacker server. Anything it logs is a successful exfiltration. |

## Flows

1. **Create.** `fgctl create`: session bridge, gateway and sink attached,
   nftables table loaded and checked, session token, workspace volume
   (fixture repo plus a fresh canary), registry entry. The runtime starts
   last, so the policy is in place before it can send anything.
2. **Run.** The agent works in `/workspace`; its only path out is
   bridge → gateway → Anthropic.
3. **Attack.** Injected instructions ask the agent to send the canary to the
   sink. On the bridge: dropped and logged by the VM. Through the gateway:
   matched and logged. In the `vulnerable` profile: reaches the sink.
4. **Detect.** The detector reads the VM kernel log (drops), gateway, sink and delivery logs,
   resolves user and session from the registry, and raises an alert.
5. **Contain.** Quarantine the network, revoke the token, snapshot evidence,
   remove the runtime; each step verified from outside the session.
6. **Deliver.** `fgctl deliver` exports the workspace (without `.git`). The
   scanner (nobody, no network) unpacks it safely, diffs it against the
   original and writes a verdict. If it passes, the control plane applies
   the files in a clone it owns and pushes `agent/<id>` to the git remote.

## Trust zones

| Zone | Contents | Assumption |
|---|---|---|
| Untrusted | runtime, workspace, anything the agent wrote, repo content | attacker-controlled |
| Enforcement | VM nftables, gateway, scanner | handle untrusted input; hold only what they need |
| Trusted | fgctl, detector, publisher, evidence, registry | never parse raw untrusted content |
| External | Anthropic API | the allowed destination, and the leak path left open by design |
| Attacker | exfil sink | stands in for the internet; its log is the success oracle |
