"use strict";

const spinner = document.getElementById("spinner");
const resultBox = document.getElementById("result-box");

function setLoading(on) {
  spinner.classList.toggle("visible", on);
  document.getElementById("btn-read").disabled = on;
  document.getElementById("btn-rotate").disabled = on;
}

function showResult(data) {
  const decision = (data.decision || "").toUpperCase();
  const isAllowed = decision === "ALLOWED";
  const badge = document.createElement("span");
  badge.className = "badge " + (isAllowed ? "allowed" : "blocked");
  badge.textContent = decision;

  resultBox.textContent = "";
  resultBox.appendChild(badge);

  const pre = document.createElement("div");
  // Safe rendering: textContent prevents XSS
  pre.textContent = JSON.stringify(data, null, 2);
  resultBox.appendChild(pre);

  resultBox.className = "result-box visible " + (isAllowed ? "allowed" : "blocked");
}

function showError(message) {
  resultBox.textContent = "";
  const errDiv = document.createElement("div");
  // textContent is safe -- no user-controlled HTML
  errDiv.textContent = "Error: " + message;
  resultBox.appendChild(errDiv);
  resultBox.className = "result-box visible blocked";
}

async function sendAction(action, riskSignal) {
  setLoading(true);
  resultBox.className = "result-box";

  try {
    const resp = await fetch("/api/demo-actions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action,
        risk_signal: riskSignal,
        tenant_id: "demo-tenant",
        agent_id: "demo-agent",
        correlation_id: crypto.randomUUID(),
      }),
    });

    if (!resp.ok) {
      showError("HTTP " + resp.status);
      return;
    }

    const data = await resp.json();
    showResult(data);
  } catch (err) {
    showError(err instanceof Error ? err.message : String(err));
  } finally {
    setLoading(false);
  }
}

document
  .getElementById("btn-read")
  .addEventListener("click", () => sendAction("demo.read_status", "normal"));

document
  .getElementById("btn-rotate")
  .addEventListener("click", () =>
    sendAction("demo.rotate_demo_key", "prompt_injection"),
  );
