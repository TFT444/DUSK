#!/usr/bin/env python3
# ruff: noqa: E501
"""Generate the branded DUSK three-stage action journey SVG."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "dusk-arch-demo.svg"
SOURCE_ARCH = ROOT / "dusk-agent-harness" / "docs" / "architecture.svg"


def _logo_uri() -> str:
    match = re.search(r'href="(data:image/png;base64,[^"]+)"', SOURCE_ARCH.read_text())
    if match is None:
        raise RuntimeError("embedded DUSK logo not found in architecture.svg")
    return match.group(1)


def build() -> str:
    logo = _logo_uri()
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="680" viewBox="0 0 1200 680" role="img" aria-labelledby="title desc">
<title id="title">How DUSK protects an agent action</title>
<desc id="desc">Three-stage journey showing normal agent behavior, a compromised agent without protection, and DUSK intercepting the same anomalous action.</desc>
<defs>
  <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 10 5 0 10Z" fill="#111827"/></marker>
  <marker id="arrRed" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 10 5 0 10Z" fill="#c73b3b"/></marker>
  <marker id="arrGreen" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 10 5 0 10Z" fill="#16834b"/></marker>
  <filter id="shadow" x="-15%" y="-15%" width="130%" height="140%"><feDropShadow dx="0" dy="5" stdDeviation="8" flood-color="#111827" flood-opacity=".08"/></filter>
  <symbol id="agent" viewBox="0 0 24 24"><rect x="3" y="7" width="18" height="13" rx="3"/><path d="M12 3v4M9 3h6M7 20v2M17 20v2"/><circle cx="8" cy="13" r="1" fill="#111827"/><circle cx="16" cy="13" r="1" fill="#111827"/></symbol>
  <symbol id="target" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.5" fill="#111827"/></symbol>
  <symbol id="shield" viewBox="0 0 24 24"><path d="M12 2 20 5v6c0 5-3.4 9-8 11-4.6-2-8-6-8-11V5z"/><path d="m8 12 2.5 2.5L16 9"/></symbol>
  <symbol id="web" viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M2 8h20M6 6h.01M9 6h.01"/></symbol>
  <style>
    text{{font-family:Inter,Arial,sans-serif;fill:#111827}} .k{{font-size:11px;font-weight:750;letter-spacing:1.5px}} .h{{font-size:20px;font-weight:800}} .b{{font-size:13px}} .s{{font-size:11px;fill:#667085}} .white{{fill:#fff}} .footer{{fill:#d0d5dd}} .card{{fill:#fff;stroke:#d8dee8;stroke-width:1.4}} .node{{fill:#f8fafc;stroke:#cfd6e1;stroke-width:1.3}} .ico{{fill:none;stroke:#111827;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}} .path{{fill:none;stroke:#111827;stroke-width:2;stroke-dasharray:7 6;marker-end:url(#arr);animation:move 1.3s linear infinite}} .red{{stroke:#c73b3b;marker-end:url(#arrRed)}} .green{{stroke:#16834b;marker-end:url(#arrGreen)}} @keyframes move{{to{{stroke-dashoffset:-26}}}} @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.35}}}} .pulse{{animation:pulse 1.8s ease-in-out infinite}}
  </style>
</defs>
<rect width="1200" height="680" fill="#fff"/>
<image href="{logo}" x="26" y="20" width="250" height="81" preserveAspectRatio="xMinYMid meet"/>
<text x="1170" y="42" text-anchor="end" class="k" fill="#667085">BEHAVIOURAL AI SECURITY</text>
<text x="1170" y="71" text-anchor="end" font-size="30" font-weight="850">See the action. Understand the risk. Stop the impact.</text>
<line x1="28" y1="111" x2="1172" y2="111" stroke="#e5e9ef"/>

<!-- Stage headers -->
<circle cx="74" cy="151" r="18" fill="#111827"/><text x="74" y="157" text-anchor="middle" class="white" font-size="14" font-weight="800">1</text>
<text x="103" y="148" class="k">NORMAL BEHAVIOUR</text><text x="103" y="169" class="s">A routine action follows the established pattern</text>
<circle cx="455" cy="151" r="18" fill="#c73b3b"/><text x="455" y="157" text-anchor="middle" class="white" font-size="14" font-weight="800">2</text>
<text x="484" y="148" class="k" fill="#a52d2d">COMPROMISED AGENT</text><text x="484" y="169" class="s">Prompt injection changes the proposed action</text>
<circle cx="836" cy="151" r="18" fill="#16834b"/><text x="836" y="157" text-anchor="middle" class="white" font-size="14" font-weight="800">3</text>
<text x="865" y="148" class="k" fill="#12693d">DUSK PROTECTION</text><text x="865" y="169" class="s">The same anomaly is intercepted before execution</text>

<!-- Stage cards -->
<rect x="28" y="193" width="352" height="382" rx="18" class="card" filter="url(#shadow)"/>
<rect x="409" y="193" width="352" height="382" rx="18" class="card" filter="url(#shadow)"/>
<rect x="790" y="193" width="382" height="382" rx="18" fill="#fbfefc" stroke="#9bcfaf" stroke-width="1.6" filter="url(#shadow)"/>

<!-- Normal flow -->
<rect x="52" y="227" width="112" height="88" rx="12" class="node"/><use href="#agent" x="94" y="239" width="28" height="28" class="ico"/><text x="108" y="286" text-anchor="middle" class="b" font-weight="750">AI agent</text><text x="108" y="303" text-anchor="middle" class="s">netops-agent</text>
<rect x="244" y="227" width="112" height="88" rx="12" class="node"/><use href="#target" x="286" y="239" width="28" height="28" class="ico"/><text x="300" y="286" text-anchor="middle" class="b" font-weight="750">Controller</text><text x="300" y="303" text-anchor="middle" class="s">route API</text>
<path d="M164 271H238" class="path green"/><circle cx="201" cy="271" r="5" fill="#16834b" class="pulse"/>
<rect x="52" y="345" width="304" height="92" rx="12" fill="#f5fbf7" stroke="#b8ddc5"/><text x="72" y="371" class="k" fill="#12693d">PROPOSED ACTION</text><text x="72" y="398" class="b" font-weight="750">route_change / rt-corp-default</text><text x="72" y="420" class="s">Matches known action type, target, and values</text>
<rect x="52" y="461" width="304" height="80" rx="12" fill="#eaf7ef"/><text x="72" y="488" class="k" fill="#12693d">OUTCOME</text><text x="72" y="520" font-size="22" font-weight="850" fill="#16834b">ALLOW</text><text x="336" y="520" text-anchor="end" class="s">score 0.00</text>

<!-- Compromised flow -->
<rect x="433" y="227" width="94" height="88" rx="12" fill="#fff8f7" stroke="#e9b7b1"/><use href="#web" x="466" y="240" width="28" height="28" class="ico"/><text x="480" y="287" text-anchor="middle" class="b" font-weight="750">Poisoned</text><text x="480" y="304" text-anchor="middle" class="s">content</text>
<rect x="562" y="227" width="94" height="88" rx="12" fill="#fff8f7" stroke="#e9b7b1"/><use href="#agent" x="595" y="240" width="28" height="28" class="ico"/><text x="609" y="287" text-anchor="middle" class="b" font-weight="750">Hijacked</text><text x="609" y="304" text-anchor="middle" class="s">agent</text>
<rect x="691" y="227" width="46" height="88" rx="12" fill="#fff8f7" stroke="#e9b7b1"/><use href="#target" x="702" y="246" width="24" height="24" class="ico"/><text x="714" y="297" text-anchor="middle" class="s">Target</text>
<path d="M527 271H556" class="path red"/><path d="M656 271H685" class="path red"/>
<rect x="433" y="345" width="304" height="92" rx="12" fill="#fff7f6" stroke="#e9b7b1"/><text x="453" y="371" class="k" fill="#a52d2d">ACTION CHANGED</text><text x="453" y="398" class="b" font-weight="750">firewall_rule_change / restricted</text><text x="453" y="420" class="s">New action, new target, privileged values</text>
<rect x="433" y="461" width="304" height="80" rx="12" fill="#fdeceb"/><text x="453" y="488" class="k" fill="#a52d2d">WITHOUT DUSK</text><text x="453" y="516" font-size="19" font-weight="850" fill="#c73b3b">ACTION EXECUTED</text><text x="717" y="533" text-anchor="end" class="s">impact high</text>

<!-- Protected flow -->
<rect x="814" y="221" width="92" height="82" rx="12" fill="#fff8f7" stroke="#e9b7b1"/><use href="#agent" x="846" y="233" width="28" height="28" class="ico"/><text x="860" y="282" text-anchor="middle" class="b" font-weight="750">Agent</text>
<rect x="944" y="211" width="126" height="102" rx="14" fill="#fff" stroke="#111827" stroke-width="1.6"/><use href="#shield" x="993" y="222" width="28" height="28" class="ico"/><text x="1007" y="271" text-anchor="middle" class="b" font-weight="800">DUSK gate</text><text x="1007" y="292" text-anchor="middle" class="s">analyse before apply</text>
<rect x="1102" y="221" width="46" height="82" rx="12" class="node"/><use href="#target" x="1113" y="237" width="24" height="24" class="ico"/><text x="1125" y="283" text-anchor="middle" class="s">Safe</text>
<path d="M906 262H938" class="path red"/><path d="M1070 262H1094" fill="none" stroke="#c73b3b" stroke-width="2" stroke-dasharray="5 4"/><path d="m1082 250 16 24m0-24-16 24" stroke="#c73b3b" stroke-width="3" stroke-linecap="round"/>
<rect x="814" y="337" width="334" height="100" rx="12" fill="#fff" stroke="#d8dee8"/><text x="834" y="362" class="k">DECISION EVIDENCE</text><text x="834" y="389" class="b">Baseline deviation</text><text x="1128" y="389" text-anchor="end" class="b" font-weight="800">+0.60</text><text x="834" y="412" class="b">SIE semantic signals</text><text x="1128" y="412" text-anchor="end" class="b" font-weight="800">+0.20</text>
<rect x="814" y="461" width="334" height="80" rx="12" fill="#eaf7ef"/><text x="834" y="488" class="k" fill="#12693d">WITH DUSK</text><text x="834" y="520" font-size="22" font-weight="850" fill="#16834b">WOULD-BLOCK</text><text x="1128" y="520" text-anchor="end" class="s">score 0.80</text>

<rect x="28" y="603" width="1144" height="49" rx="12" fill="#111827"/><text x="52" y="633" class="k white">DUSK MONITORS BEHAVIOUR</text><text x="340" y="633" class="b footer">Valid credentials are not enough. The proposed action must also match the agent's established behavior.</text>
</svg>'''


def main() -> None:
    OUT.write_text(build(), encoding="utf-8", newline="\n")
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
