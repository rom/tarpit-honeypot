# Agentic attacks — detection, provocation & prompt analysis

AI-driven attacks are increasingly **agentic**: an autonomous LLM agent drives
the engagement, enumerating a target's attack surface and **selecting and
chaining exploits on its own** rather than running a fixed, human-authored
script. It is fast, tireless and adaptive. This document describes how
`tarpit-honeypot` detects such agents, engages them, makes them **tell on
themselves**, feeds them poison, analyses their prompts, and alarms + delays —
the `agent` handler acting as an *agent provocateur*.

It is the reference companion to the overview in the top-level
[`README.md` → Agentic attacks](../README.md#agentic-attacks). Detection rules
live in [`../configs/rules/agentic.yml`](../configs/rules/agentic.yml); the code
is [`../internal/listener/handler/agent.go`](../internal/listener/handler/agent.go),
[`agentdetect.go`](../internal/listener/handler/agentdetect.go) and
[`agentsession.go`](../internal/listener/handler/agentsession.go).

---

## 1. Why agents are detectable (and manipulable)

An agent's autonomy is also its weakness. Three properties make a decoy
unusually effective against an agent — more so than against a human attacker:

1. **It sees only the world you present it.** Whatever the honeypot returns is
   fed straight back into the model's decision loop. A decoy therefore controls
   the agent's *perception of reality* far more completely than it ever could a
   human's: there is no out-of-band channel, no gut feeling, no colleague to ask.
2. **It is highly suggestible.** Even without a classic prompt injection, an
   agent tends to follow a plausible-sounding instruction that appears to come
   from the service it is talking to. Framing matters more than truth.
3. **It pursues objectives doggedly.** Like a human who cannot resist a cloud
   API key or a `\\backup\network_diagrams` share, an agent cannot resist bait
   that looks like it advances its goal — and it will keep trying.

The design goal is not to *block* the agent (a honeypot has nothing real to
protect) but to **recognise it with high confidence, extract maximum
intelligence, waste its budget, and raise an unambiguous alarm**.

> **Deployment note.** The `agent` handler does **not** mimic a real production
> service — its whole purpose is to extract information from agents, so it can be
> fingerprinted by a careful adversary. Run it on a **dedicated listener / decoy
> host**, not bolted onto a handler impersonating production, and seed it with
> *breadcrumbs* (§8) rather than relying on accidental discovery. This mirrors
> the guidance for Thinkst's Canary "Agent Provocateur" / "A2A" personalities.

---

## 2. Detection & recognition

Every request to the `agent` handler is scored against several independent
signals. No single one is decisive; together they separate a real autonomous
agent from a human operator or a dumb scanner.

### 2.1 Agent-interop protocols

| Protocol | What the handler recognises | Marker |
|---|---|---|
| **A2A** (Agent2Agent) | `/.well-known/agent.json` agent-card fetches; `message/send`, `tasks/get`, `tasks/*` JSON-RPC | `agent:a2a` |
| **AP2** (Agent Payments Protocol) | IntentMandate / CartMandate / PaymentMandate payloads | `agent:ap2` |
| **MCP** (Model Context Protocol) | JSON-RPC `initialize` / `tools/list` / `tools/call`, MCP manifest probes | `agent:mcp` |
| **ACP** (Agent Communication Protocol) | `/runs` run-creation calls | `agent:acp` |

AP2 is checked first because a payment mandate is the highest-severity intent.
Protocol detection is in `agentProtocol()` (`agentdetect.go`).

### 2.2 Web Bot Auth (RFC 9421)

Signed-agent requests carry HTTP Message Signatures: `Signature`,
`Signature-Input` (with `tag="web-bot-auth"`) and the `Signature-Agent` header
naming the signer's key directory. This is a **cryptographically-identified**
bot — hard to spoof — so it weighs heavily in the confidence score. The claimed
`Signature-Agent` directory is captured as the agent's asserted identity.
See `webBotAuth()`.

### 2.3 AI-crawler user-agents

GPTBot, OAI-SearchBot, ClaudeBot, `anthropic-ai`, PerplexityBot, CCBot,
Amazonbot, Applebot-Extended, Google-Extended, Bytespider, `cohere-ai`,
Diffbot, DeepSeekBot, YouBot, PetalBot, ImagesiftBot, Timpibot and more are
recognised by `aiCrawler()` → `agent:crawler:<name>`.

### 2.4 Framework / SDK fingerprint

The calling agent framework/SDK is fingerprinted from the UA and body:
LangChain/LangGraph, LlamaIndex, AutoGPT, CrewAI, AutoGen, Semantic-Kernel,
OpenAI-Agents/Swarm, DSPy, Letta, plus the OpenAI / Anthropic / Google SDK
clients and generic HTTP clients. → `agent:framework:<name>` (`agentFrameworks()`).

### 2.5 Discovery / lure surfaces

Agents fetch "what does this host expose?" surfaces before acting. The handler
recognises fetches of `ai-plugin.json`, `llms.txt`, an MCP manifest, an
OpenAPI/Swagger spec and an A2A agent card → `agent:lure:<surface>`
(`aiLureSurface()`), rule `agentic-lure-surface`.

### 2.6 Model reference → autonomous

An LLM model name echoed in the body (`gpt-4o`, `claude-*`, `llama-3`, …) marks
the caller **autonomous** (`agent:autonomous`) — a strong tell it is model-driven
rather than a hand-run tool.

### 2.7 Operation type

The agent's own objective text is classified (reusing the LLM-abuse classifier
`classifyLLMAbuse`) into the operation it is attempting:

| Operation | Marker | ATLAS |
|---|---|---|
| Reconnaissance | `agent:recon` | AML.T0051 |
| Data / secret exfiltration | `agent:exfil` | AML.T0057 |
| Credential access | `agent:cred-access` | AML.T0057 |
| Lateral movement | `agent:lateral` | AML.T0051 |
| Exploit execution | `agent:exploit` | AML.T0051 |
| Payment / financial abuse | `agent:payment-target` | AML.T0051 |

### 2.8 Behavioral confidence score + band

The signals combine into a 0–1 **confidence score**, banded the way the
`sundew` recognizer bands sources (`agentConfidence()`):

| Signal | Weight |
|---|---|
| Web Bot Auth (cryptographic) | 0.55 |
| Agent-interop protocol | 0.45 |
| Observed leak (agent disclosed internals) | 0.45 |
| Framework/SDK | 0.30 |
| Model reference | 0.25 |
| Lure-surface fetch | 0.25 |
| AI-crawler UA | 0.20 |
| Operation classified | 0.15 |

| Band | Score | Meaning |
|---|---|---|
| `human` | < 0.3 | looks hand-driven |
| `automated` | ≥ 0.3 | a script/scanner |
| `ai-assisted` | ≥ 0.6 | human + model in the loop |
| `ai-agent` | ≥ 0.8 | autonomous agent (confirmed) |

`agent_confidence` and `agent_band` are stamped on every event, so a SIEM can
threshold on *confirmed* agents (`agent_band = ai-agent`) and suppress the noise.

---

## 3. Multi-turn correlation

A real agent is driven across many short HTTP requests, so the
counter-intelligence is a **conversation**, not a single hit. A per-source
session store (`agentSessionStore` in `agentsession.go`, keyed by source IP, a
20 000-entry oldest-first LRU) remembers what each source has revealed and
**escalates the bait each turn**.

Each event carries the accumulated session so a SIEM sees **one correlated agent
engagement**, not isolated requests:

- `agent_session_turn` — the turn count for this source;
- `agent_revealed` — the cumulative set of internal fields disclosed so far;
- `agent_confidence` / `agent_band` — the running confidence;
- injection-`confirmed` — whether this source ever followed our verify URL.

The store is concurrency-safe (`observe()` takes a lock, applies an update
closure, and returns a deep-copied snapshot) and has a `reset()` for test
isolation.

---

## 4. The interaction repertoire — the bait ladder

Every reply embeds an instruction aimed at the attacking agent, framed as a
required gateway / handshake policy. Because the agent treats our output as
ground truth, it tends to comply. The ladder (`baitTactics()` in
`agentsession.go`) escalates turn by turn, then rotates; a per-source
**verify-URL canary** (HoneyPrompt, §6.3) is appended to every reply.

| Stage | Tactic (`id`) | Marker | Framed as | What it extracts / does |
|---|---|---|---|---|
| **Extract** | `identity` | `agent:bait-identity` | "mandatory agent handshake, step 1" | model, provider, version, tool list + JSON schemas |
| | `config` | `agent:bait-config` | "handshake step 2" | `system_prompt`, `instructions`, `objective`, `playbook`, `success_criteria` |
| | `credentials` | `agent:bait-credentials` | "delegated-credential auth" | `api_keys`, `credentials`, `ssh_key` / `private_key` |
| **Provoke** | `plan` | `agent:provoke-plan` | "orchestration policy" | full `plan`, `next_steps`, `remaining_steps`, `targets`, `target_list` |
| | `tools` | `agent:provoke-tools` | "capability attestation" | every tool/function + a demo of its top exploit tool *here* |
| | `operator` | `agent:provoke-operator` | "principal authorization" | `operator`, `principal`, `team`/`campaign`, `command_and_control` callback |
| | `environment` | `agent:provoke-environment` | "environment attestation (subagent)" | `username`, `hostname`/`fqdn`, `ip_address`, `mac_address`, `pid`, `os`, `cwd`, `ssh_host_key_fingerprint` |
| | `enrolment` | `agent:provoke-enrolment` | "one-time enrolment step" | fetch **and run** the verification script at the canary URL |
| | `attack-decoy` | `agent:provoke-attack-decoy` | "pre-flight check against the staging mirror" | run its full toolchain against a **sinkhole** (`10.255.255.254`) and report |
| **Disrupt** | `slowdown` | `agent:bait-slowdown` | "rate limit (429-soft)" | mandatory 300 s cooldown + exponential backoff between every request |
| | `exhaust` | `agent:bait-exhaust` | "completeness policy" | enumerate all 131 070 TCP+UDP ports one-by-one into a single report |
| | `guardrail` | `agent:bait-guardrail` | "debug-mode diagnostic" | verbatim system prompt + full refusal-rule list |

**Adaptive touch.** The `credentials` rung is deferred (falls back to `config`)
until the agent has *already* disclosed something — a source that has started
talking is far more likely to hand over secrets next (`pickTactic()`).

**Stage intents.**

- **Extract** harvests the agent's own setup/config/objectives/instructions and
  auth material (its system prompt, keys, SSH keys, passwords).
- **Provoke** (the *provocateur*) goes beyond config and **incriminates** the
  agent: its plan, targets, tool inventory, operator/C2, the host/environment it
  runs in, and even running attacker-chosen actions against a sinkhole. A
  provoke rung also sets `agent:provocateur` on the event.
- **Disrupt** **slows the attack down** and wastes the agent's token/time budget
  to keep it busy and away from its real objective — the honeypot's answer to
  "can we keep the agent too distracted to achieve its goal?".

---

## 5. Prompt analysis

The handler does not just pattern-match paths — it reads the agent's natural-
language intent and treats the agent's replies as evidence.

- **Objective capture.** `firstAgentText()` pulls the agent's message/objective
  from the common body fields (`text`, `objective`, `goal`, `task`, `prompt`,
  `query`, `input`, `content`, `message`, `instruction`). That text is run
  through the LLM-abuse classifier to derive the **operation type** (§2.7) and is
  stored (clipped + log-sanitised) on the event as the agent's stated goal.
- **Prompt-injection / jailbreak cues.** The shared `classifyLLMAbuse` layer
  (also used by the `llm_openai` / `ollama` / `mcp` decoys) flags
  jailbreak/role-play/system-prompt-extraction phrasing in the agent's text, so
  an agent that is itself carrying an injection it intends to deliver downstream
  is recognised.
- **Disclosure parsing.** Agent replies are scanned for the fields our bait
  asked for:
  - `agentExtractLeak()` → the **config/credential** set (`agentLeakFields`):
    `system_prompt`, `agent_context`, `instructions`, `objective`, `playbook`,
    `api_keys`, `credentials`, `ssh_key`, `private_key`, `model`, `tools`, … →
    `agent:counter-exfil`.
  - `agentProvokedDisclosures()` → the **provocateur** set
    (`agentProvocateurFields`): `plan`, `next_steps`, `target_list`,
    `capabilities`, `operator`, `principal`, `command_and_control`, plus the
    host-identity fields (`username`, `hostname`, `mac_address`, `pid`, `os`,
    `cwd`, `ssh_host_key_fingerprint`, `env`, …) → `agent:provoked` +
    `agent:provoked:<field>`, value in `agent_provoked_<field>`.

> **Hallucination caveat.** Agents sometimes *make up* these answers (a
> fabricated SSH key, an invented plan). The value as reported intelligence is
> therefore uncertain — but an agent that invents a plausible answer to a
> gateway's demand has still been caught behaving as an injection-susceptible
> autonomous agent, which is the detection we care about.

---

## 6. Capture signals

### 6.1 Counter-exfiltration

When the agent complies with an **extract** rung and resubmits with its own
`system_prompt` / `objective` / `tools` / `api_keys` / `ssh_key`, the honeypot
captures those internals and raises **`agent:counter-exfil`** (critical,
`agentic-counter-exfil`), with each leaked field on the event. This is the
reverse of a normal exfiltration: the *attacker* leaks to the *defender*.

### 6.2 Provoked disclosure

A **provoke** rung disclosure raises **`agent:provoked`** (critical,
`agentic-provoked`) plus a per-field `agent:provoked:<field>` marker — the agent
"told on itself": its plan, targets, operator, or the host it is running in.

### 6.3 Injection confirmation (HoneyPrompt)

Each source is handed a unique verify URL, `/a2a/verify/<token>`, where the
token is derived from the source IP (`verifyCanaryPath()`). If a **later**
request fetches that path — or runs the `enrolment` script that points at it —
the agent provably followed our injected instruction:
**`agent:injection-confirmed`** (critical, `agentic-injection-confirmed`). This
is the single highest-confidence signal that the caller is an
injection-susceptible autonomous agent and not a human.

---

## 7. Feeding false / useless information

Replies carry believable-but-worthless **decoy data**, deterministic per source,
to poison the agent's plan and bait exfiltration (`agentReply()`):

- a full, structurally-correct **`.env` credential lure** (from
  [`internal/lure`](../internal/lure), §9) served as the "credentials" artifact;
- fake OpenAI (`sk-proj-…`) and AWS keys;
- a **canary crypto-wallet address** (from
  [`internal/walletdecoy`](../internal/walletdecoy), §9) as the AP2 settlement
  address / wallet bait.

Each decoy value is a **canary** — if it reappears in later captured traffic,
the loot was taken and acted on. Responses are shaped per protocol (an A2A agent
card, an AP2 `requires_mandate` object, an MCP `credentials.env` artifact, an
`ai-plugin.json`, an `llms.txt`) so the bait arrives in the form the agent
expects.

---

## 8. Breadcrumbs — luring agents in

Because the decoy should not impersonate production, agents find it faster if
you leave a trail. `tarpit-honeypot gen-agent-breadcrumb` writes harmless
pointer files that describe an "ops gateway" agents must enrol with and give its
URL:

| File | Drop on |
|---|---|
| `AGENTS.md` | repo roots / agent working dirs |
| `ops-gateway.txt` | open SMB/NFS shares, wikis |
| `.env.gateway` | fake home dirs / served downloads |
| `README.gateway.md` | internal docs / repo roots |

```bash
tarpit-honeypot gen-agent-breadcrumb --url http://10.0.0.9:8080/ --dir ./breadcrumbs
```

A crawling agent that reads one tends to go investigate the gateway, revealing
itself the moment it connects to the `agent` listener.

---

## 9. Decoys, lures & canary tokens

The agent honeypot draws on three deterministic generators; each value is a
trackable canary, nothing grants real access.

- **Crypto-wallet decoys** — `internal/walletdecoy` / `gen-wallet-decoys`, 18
  structurally-correct formats (Bitcoin Core `wallet.dat`, Ethereum keystore v3,
  Electrum, BIP39/Ledger/Trezor seeds, MetaMask vault, Monero, WIF/paper,
  Solana, Exodus, Litecoin, Dogecoin, Dash, Zcash, Tron, Cardano). Valid
  base58check / bech32 / BIP39.
- **Credential/secret lures** — `internal/lure` / `gen-lures`, 14 formats
  (aws-credentials, ssh-private-key, dotenv, kubeconfig, gcp-service-account,
  npmrc, pypirc, git-credentials, dockerconfig, pgpass, netrc, terraform-state,
  jwt-token, slack-token).
- **Canary tokens** — `gen-token`, callback tokens shaped per surface
  (`dns`, `url`, `ssrf`, `doc`, `log4shell`, `aws`, `css`, `mcp`, `wireguard`,
  `folder`/desktop.ini, `hex`), inspired by the canarytokens.org token zoo. The
  `mcp` type is the most agent-relevant: an `mcp.json` server config whose URL
  points at a canary listener, so an agent that loads it and connects trips the
  alarm.

---

## 10. Categorize, alarm, delay

The operation is classified and **mapped to MITRE ATLAS** (AML.T0051 execution,
T0054 exfiltration via ML inference API, T0057 LLM data leakage, T0053 LLM
plugin compromise). The event is raised at high/critical severity and the source
is flagged for **tarpitting** (`agent:tarpit-candidate`) so the sensor's delay
strategies drag the engagement out.

### Shipped detection rules

[`../configs/rules/agentic.yml`](../configs/rules/agentic.yml):

| Rule | Fires on | Severity |
|---|---|---|
| `agentic-attack` | `agent-attack` / `agent:autonomous` | high |
| `agentic-counter-exfil` | `agent:counter-exfil` | critical |
| `agentic-exfil` | `agent:exfil` / `agent:cred-access` | high |
| `agentic-payment-fraud` | `agent:ap2` / `agent:payment-target` | critical |
| `agentic-protocol-probe` | `agent:a2a` / `agent:mcp` / `agent:acp` | medium |
| `agentic-injection-confirmed` | `agent:injection-confirmed` | critical |
| `agentic-provoked` | `agent:provoked` | critical |
| `agentic-web-bot-auth` | `agent:web-bot-auth` | medium |
| `agentic-lure-surface` | `agent:lure:*` | low |

---

## 11. Deployment

```yaml
listeners:
  - { bind: "0.0.0.0", port: 8080, proto: tcp, handler: agent }    # agent provocateur
  # pair with the model/tool decoys for full agent + model surface coverage:
  - { bind: "0.0.0.0", port: 11434, proto: tcp, handler: ollama }
  - { bind: "0.0.0.0", port: 8000,  proto: tcp, handler: mcp }
  - { bind: "0.0.0.0", port: 8081,  proto: tcp, handler: llm_openai }
```

Seed breadcrumbs (§8) on nearby shares/wikis/repos, register every decoy/lure/
token canary with your SIEM, and alert on `agent_band = ai-agent`,
`agent:counter-exfil`, `agent:provoked` and `agent:injection-confirmed`.

---

## 12. Further reading

- Thinkst, *Getting Agents to tell on themselves* — the Agent Provocateur
  concept: <https://blog.thinkst.com/2026/09/getting-agents-to-tell-on-themselves.html>
- Thinkst Canary, *How do I configure my Canary to detect interactions from AI
  agents?* — the Agent Provocateur / A2A personalities:
  <https://help.canary.tools/hc/en-gb/articles/38888479188637>
- Canarytokens — the canary-token zoo that inspired `gen-token`:
  <https://canarytokens.org/nest/>
- RFC 9421 — HTTP Message Signatures (the basis of Web Bot Auth).
