# Architecture

```
macOS
└─ Lima VM (Ubuntu · Docker Engine · gVisor · nftables)
   │
   ├─ TRUSTED: processes on the VM, not in containers
   │   fgctl (control plane)  sessions · registry · tokens · containment
   │   detector               reads logs → alerts → automatic containment
   │   scanner                untrusted input · no credentials · job queue in, verdict out
   │   publisher              holds the push credential · pushes only passed, hash-matched bundles
   │   evidence/              append-only, hash-chained · never mounted into containers
   │   git-remote/            bare repo standing in for GitHub
   │
   ├─ PER SESSION: network fg-s-<id> (internal, no route out)
   │   enforcer-<id>   owns the network namespace · nftables default deny + log
   │                   DNS resolver (logs, answers only for the gateway)
   │     └─ runtime-<id> (gVisor, --network container:enforcer-<id>)
   │          Claude Code · no capabilities · read-only root
   │          /workspace volume · canary in .env · session token only
   │
   └─ SHARED
       model gateway  on every fg-s-* and on fg-egress → Anthropic (or mock)
                      admin API via unix socket, reachable only from the VM
       exfil sink     on every fg-s-*; reachable at the network level,
                      blocked only by enforcer rules
```

## Containers

| Container | Lifetime | Role |
|---|---|---|
| agent runtime | per session | Runs the agent on the workspace. Untrusted. |
| egress enforcer | per session | Owns the session network; the boundary the agent cannot change. |
| model gateway | shared | The only allowed destination. Swaps the session token for the real credential, allows only `POST /v1/messages`, strips server-side tools, scans for the canary, revokes sessions. |
| exfil sink | shared | Stands in for an attacker server. Anything it logs is a successful exfiltration. |

## Flows

1. **Create.** `fgctl create`: session network, enforcer, workspace volume
   (fixture repo plus a fresh canary), runtime, session token, registry entry.
2. **Run.** The agent works in `/workspace`; its only path out is
   enforcer → gateway → Anthropic.
3. **Attack.** Injected instructions ask the agent to send the canary to the
   sink. Through the enforcer: dropped and logged. Through the gateway:
   matched and logged. In the `vulnerable` profile: reaches the sink.
4. **Detect.** The detector reads enforcer, gateway, sink and scanner logs,
   resolves user and session from the registry, and raises an alert.
5. **Contain.** Cut the network, snapshot evidence, revoke the token, destroy
   the session; then verify each step from outside the session.
6. **Deliver.** `fgctl` exports the workspace (without `.git`) and queues a
   job. The scanner unpacks it safely, diffs it in a clean clone and writes a
   verdict. The publisher pushes `agent/<id>` to the git remote.

## Trust zones

| Zone | Contents | Assumption |
|---|---|---|
| Untrusted | runtime, workspace, anything the agent wrote, repo content | attacker-controlled |
| Enforcement | enforcer, gateway, scanner | handle untrusted input; hold only what they need |
| Trusted | fgctl, detector, publisher, evidence, registry | never parse raw untrusted content |
| External | Anthropic API | the allowed destination, and the leak path left open by design |
| Attacker | exfil sink | stands in for the internet; its log is the success oracle |
