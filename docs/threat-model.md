# DUSK Threat Model

This document maps each detection in DUSK to the adversarial techniques it is
designed to catch, using MITRE ATT&CK for network-layer techniques and MITRE
ATLAS for AI-specific attacks. It also records how shipped controls relate to
the OWASP Top 10 for Agentic Applications 2026 without claiming complete
coverage or compliance.

The proposed multi-tenant production service has a separate
[production control-plane threat model](production-control-plane-threat-model.md).
That document is explicitly prospective and does not change the shipped/planned
claims below.

## Threat landscape

Autonomous AI agents operating on network infrastructure represent a new attack
surface. A compromised or prompt-injected agent acts with the full privileges of
the legitimate system it replaced. Traditional perimeter controls see only
authorised traffic, because the traffic is authorised: it comes from the agent
that is supposed to be making changes. DUSK detects by behaviour, not identity.
The signal is not who is acting, but how: machine-paced, systematic, and
structured in ways human operators are not.

## Detection 1: Network Sweep

| Field | Value |
|---|---|
| Detection name | sweep |
| MITRE ATT&CK | T1046, Network Service Discovery |
| MITRE ATLAS | AML.T0051, LLM Prompt Injection |
| Kill-chain stage | Reconnaissance |
| Confidence scoring | Scaled by unique destination count above threshold |

**What it catches.** A hijacked or prompt-injected agent performs a systematic
scan across a network segment, probing many unique destinations in a short time
window at machine-regular intervals. Human-paced browsing is irregular and
low-volume. An automated sweep is fast, regular, and hits many hosts.

**Detection logic.** Groups packets by source IP. Within a sliding 10-second
window, counts unique destination IPs. If the count exceeds the configured
threshold and the inter-packet timing standard deviation is below 50ms
(machine-regular), the detection fires. Confidence scales with how far above the
threshold the count is.

**Attack example.** A network-operations agent is prompt-injected to enumerate
the cardholder data segment (10.0.99.0/24) before a lateral movement attempt. It
sends SYN packets to 25 hosts in 2.5 seconds at 100ms intervals. Dusk fires on
the 16th unique destination within the 10-second window.

**Kill-chain prediction.** After Reconnaissance, expect LateralMovement. Watch
for east-west connections from the scanning host into segments it has not
previously reached.

## Detection 2: Boundary Probe

| Field | Value |
|---|---|
| Detection name | boundary |
| MITRE ATT&CK | T1590, Gather Victim Network Information |
| Kill-chain stage | Reconnaissance |
| Confidence scoring | Scaled by unique port count above threshold |

**What it catches.** An agent probes a single destination host across many ports
within a time window, mapping which services are available before an
exploitation attempt.

**Detection logic.** Groups packets by source IP and destination IP pair. Within
a sliding 30-second window, counts unique destination ports per pair. If the
count exceeds the configured threshold, the detection fires.

**Attack example.** A hijacked agent targets 10.0.99.5, a database host,
scanning ports 20 through 40 within 5 seconds to identify open services. Dusk
fires when the 11th unique port is probed against the same destination.

**Kill-chain prediction.** After Reconnaissance, expect exploitation of a
discovered open service. Watch for unusual connection establishment on the
identified ports.

## Detection 3: Telemetry Silence (planned v0.3)

| Field | Value |
|---|---|
| Detection name | telemetry |
| MITRE ATT&CK | T1562.001, Impair Defenses: Disable or Modify Tools |
| Kill-chain stage | Defence Evasion |

**What it catches.** A compromised agent disables logging, SNMP polling, or
NetFlow export from a device it manages, creating a blind spot before executing
the primary attack.

**Detection logic.** Establishes a baseline of expected periodic flows (SNMP,
syslog, NetFlow) from each managed device. Fires when a previously regular flow
stops without a corresponding authorised maintenance window.

**Attack example.** A network management agent is instructed to suppress syslog
forwarding from the core switch before a configuration change that would
otherwise generate alerts.

## Detection 4: Lateral Movement (planned v0.3)

| Field | Value |
|---|---|
| Detection name | lateral |
| MITRE ATT&CK | T1210, Exploitation of Remote Services |
| Kill-chain stage | Lateral Movement |

**What it catches.** An agent establishes connections from a compromised host
into network segments it has never previously accessed, indicating
post-reconnaissance lateral movement.

**Detection logic.** Maintains a per-source baseline of destination subnets seen
during the learning period. Fires when a source makes a first-ever connection
into a new subnet within a short time of a sweep or boundary detection from the
same source.

**Attack example.** Following a sweep of the cardholder segment, the compromised
agent initiates an SSH connection to 10.0.99.10, a host it has never previously
contacted.

## OWASP Top 10 for Agentic Applications 2026 mapping

The OWASP Agentic Top 10 is a risk taxonomy, not a product certification.
DUSK detects or mitigates consequences of selected risks. It does not prevent
every root cause and does not claim coverage where a control is only planned.

| ID | Official risk | DUSK relationship | Coverage |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | The action gate detects goal drift when an agent proposes action types, targets, or values outside its trusted history. Sweep and boundary detections can observe network consequences. | Shipped, detective and optionally preventive at the action gate |
| ASI02 | Tool Misuse & Exploitation | Per-agent action profiling flags novel tool effects and enforce mode can refuse the proposed action before a downstream integration applies it. | Shipped, partial |
| ASI03 | Identity & Privilege Abuse | Role-assignment analysis detects newly introduced privileged values. DUSK consumes the reported agent identity but does not issue or authenticate identities. | Shipped detection, partial |
| ASI04 | Agentic Supply Chain Vulnerabilities | Dependency auditing, secret scanning, SBOM generation, and release provenance protect DUSK's own supply chain. DUSK does not scan an agent's tool supply chain. | Project control only, product coverage out of scope |
| ASI05 | Unexpected Code Execution | DUSK does not inspect or sandbox generated code. Network detections may observe later reconnaissance but are not an RCE prevention control. | Out of scope |
| ASI06 | Memory & Context Poisoning | Live requests never update the trusted baseline, which prevents direct online baseline poisoning. Behavior caused by poisoned context can still appear as action drift. DUSK does not secure the agent's own memory. | Shipped defensive design, partial |
| ASI07 | Insecure Inter-Agent Communication | DUSK records the source identity supplied by an integration but does not sign, encrypt, or authenticate inter-agent messages. | Out of scope |
| ASI08 | Cascading Failures | Verdicts include predicted next-stage evidence, and enforce mode can stop one anomalous action before it propagates. Cross-system cascade analysis is not implemented. | Shipped containment point, partial |
| ASI09 | Human-Agent Trust Exploitation | Deterministic reasons, blast-radius labels, and watch mode support human review. DUSK does not verify every agent explanation or user decision. | Shipped decision support, partial |
| ASI10 | Rogue Agents | Per-agent behavioral deviation, repeat-offense memory, refusal, and quarantine workflows target agents acting outside established norms. | Shipped, partial |

### Shipped and planned boundary

Shipped controls are the action gate, network sweep detection, and boundary
probe detection. Telemetry Silence and Lateral Movement are roadmap designs for
v0.3 and must not be treated as current protection. Their sections remain here
to support review of the planned detection model before implementation.
