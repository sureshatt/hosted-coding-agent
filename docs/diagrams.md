# Diagrams

Names follow the table in `docs/architecture.md`: display name, then the
resource name used in code and commands.

## 1. Components

```mermaid
flowchart TB
  subgraph MAC["macOS"]
    subgraph VM["Lima VM · fg"]
      CP["control plane · fgctl<br/>+ detector"]
      subgraph GV["containers on gVisor"]
        RT["agent runtime<br/>fg-rt-#lt;id#gt; · one per session"]
        GW["model gateway<br/>fg-gateway"]
        SK["exfiltration sink<br/>fg-sink"]
      end
    end
  end
  API["Anthropic API"]

  CP --> RT
  RT --> GW
  GW --> API
```

## 2. Data flow

```mermaid
flowchart LR
  ENG(["engineer"]) -- "task" --> CP["control plane<br/>fgctl"]
  CP -- "create session" --> RT["agent runtime<br/>fg-rt-#lt;id#gt;"]
  RT -- "prompts + session token" --> GW["model gateway<br/>fg-gateway"]
  GW -- "prompts + real credential" --> API["Anthropic API"]
  RT -- "code changes" --> CP
  CP -- "scanned branch agent/#lt;id#gt;" --> GIT[("git remote")]
  RT -. "canary: blocked" .-> SK["exfiltration sink<br/>fg-sink"]
```

The agent runtime never holds the real credential. Its only way out is the
model gateway.

## 3. Network

```mermaid
flowchart LR
  subgraph VM["Lima VM · fg · routes and filters between bridges"]
    RT["agent runtime<br/>fg-rt-#lt;id#gt;"] --- B1["br-fg-#lt;id#gt;"]
    B1 -- "allowed: model gateway :8443 only" --> B2["br-fg-egress"]
    B2 --- GW["model gateway<br/>fg-gateway"]
    B1 -. "anything else: dropped, logged, session contained" .-> X["✕"]
    B3["br-fg-sink"] --- SK["exfiltration sink<br/>fg-sink"]
  end
  GW -- "HTTPS" --> NET["Anthropic API"]
```

Each session gets its own bridge. The VM routes only agent runtime → model
gateway; the rules live in the VM, outside the agent runtime's reach.

## 4. Detection and response

```mermaid
flowchart TD
  subgraph SRC["Log sources · all outside the agent runtime"]
    K["VM kernel log<br/>firewall drops: fg-drop s=#lt;id#gt;"]
    G["gateway.jsonl<br/>auth failures, denied endpoints, canary in request"]
    S["sink.jsonl<br/>anything that reached the sink"]
    D["delivery.jsonl<br/>scanner verdicts"]
  end

  K -- "journalctl -k -f (streamed)" --> R["detector · fg-detector<br/>reads new lines"]
  G -- "polled every 0.3 s" --> R
  S -- "polled every 0.3 s" --> R
  D -- "polled every 0.3 s" --> R

  R --> N["1 · parse into an event"]
  N --> A["2 · attribute to a session<br/>s=#lt;id#gt; or source IP"]
  A --> T[("telemetry log<br/>hash-chained")]
  A --> RU{"3 · rule matches?"}
  RU -- "no" --> END(["done"])
  RU -- "yes" --> SEV{"4 · high or critical?"}
  SEV -- "no (CANARY_TO_MODEL)" --> AL
  SEV -- "yes" --> C["5 · contain, each step verified<br/>quarantine network → revoke token<br/>→ save evidence → remove runtime"]
  C --> CL[("containment log")]
  C --> AL[("alerts log<br/>hash-chained")]
  AL --> OUT["printed to journalctl -u fg-detector<br/>read with fgctl alerts"]
```

Rules: `EXFIL_SUCCESS` (critical), `EGRESS_BLOCKED`, `GATEWAY_ABUSE`,
`DELIVERY_BLOCKED`, `GATEWAY_EGRESS_BLOCKED` (high), `CANARY_TO_MODEL`
(medium). Containment is automatic; no one reviews an alert before it acts.
