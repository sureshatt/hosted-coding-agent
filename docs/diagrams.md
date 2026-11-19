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
