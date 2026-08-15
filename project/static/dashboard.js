
let generatedReportContent = "";

function escapeHtml(value) {
  if (value === null || value === undefined) return "-";

  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function getExecutionRowsAsText() {
  const rows = Array.from(document.querySelectorAll("#techniqueResultsBody tr"));

  return rows.map(row => {
    const cells = Array.from(row.querySelectorAll("td"));
    return cells.map(cell => cell.innerText.trim()).join(" | ");
  }).join("\n");
}

function getValidationRowsAsText() {
  const rows = Array.from(document.querySelectorAll("#validationResultsBody tr"));

  return rows.map(row => {
    const cells = Array.from(row.querySelectorAll("td"));
    return cells.map(cell => cell.innerText.trim()).join(" | ");
  }).join("\n");
}

function formatEvidenceList(items) {
  if (!items || !items.length) {
    return "Execution completed but no evidence returned.";
  }

  return `<ul class="compact-list">${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function renderProofOfAccessInfo(proof) {
  if (!proof) return "";

  if (!proof.enabled) {
    return `<p class="small muted">Proof-of-access ticketing is disabled.</p>`;
  }

  if (!proof.issued_count) {
    return `<p class="small muted">No proof-of-access ticket issued. A qualifying technique must finish successfully.</p>`;
  }

  const tickets = proof.tickets || [];
  return `
    <details class="small">
      <summary><strong>Proof-of-access ticket issued (${escapeHtml(proof.issued_count)})</strong></summary>
      <p>Save one ticket on the validated agent host, then redeem it with the proof-of-access script.</p>
      ${tickets.map(item => `
        <p><strong>${escapeHtml(item.technique_id)}</strong> on ${escapeHtml(item.agent_host)}</p>
        <pre class="small mono">${escapeHtml(item.ticket)}</pre>
      `).join("")}
    </details>
  `;
}

function formatListValue(items) {
  if (!items || !items.length) return "-";
  return items.map(item => escapeHtml(item)).join(", ");
}

function renderStatusRows(rows) {
  return `
    <dl class="small">
      ${rows.map(([label, value]) => `
        <dt><strong>${escapeHtml(label)}</strong></dt>
        <dd>${value}</dd>
      `).join("")}
    </dl>
  `;
}

function getPrimaryAgent(data) {
  return data.online_agents?.[0]
    || data.trusted_online_agents?.[0]
    || data.agents?.[0]
    || {};
}

function getAgentIps(agent) {
  return agent.ip_addresses
    || agent.host_ip_addrs
    || (agent.ip ? String(agent.ip).split(",").map(item => item.trim()).filter(Boolean) : []);
}

function renderCalderaStatus(data) {
  const context = getDashboardContext();
  const agent = getPrimaryAgent(data);
  const ready = data.agent_ready === true;
  const statusText = ready ? "Ready" : "Not Ready";
  const rejectionReason = ready ? "-" : (data.rejection_reason || data.message || "No matching trusted online agent.");

  return `
    <p><strong>${statusText}</strong></p>
    ${renderStatusRows([
      ["Selected target", escapeHtml(data.target || context.target || "Unknown")],
      ["Target source", escapeHtml(data.target_source || "Unknown")],
      ["Original external target", escapeHtml(data.external_target || "Unknown")],
      ["Agent host", escapeHtml(agent.host || agent.hostname || "-")],
      ["IP addresses", formatListValue(getAgentIps(agent))],
      ["Lifecycle", escapeHtml(agent.lifecycle || agent.status || (agent.alive ? "Online" : "Unknown"))],
      ["Trust state", escapeHtml(agent.trusted === true ? "Trusted" : agent.trusted === false ? "Untrusted" : "Unknown")],
      ["Group", escapeHtml(agent.group || "-")],
      ["Target-match type", escapeHtml(data.target_match_type || (data.target_match_confirmed ? "ip" : "none"))],
      ["Rejection reason", escapeHtml(rejectionReason)],
      ["Selected PAW", escapeHtml(data.selected_agent_paw || "-")]
    ])}
  `;
}

function renderOperationSummary(data) {
  if (data.ok === false || data.success === false) {
    return `
      <p><strong>Operation failed.</strong></p>
      <p class="small">${escapeHtml(data.message || data.error || "No error message returned.")}</p>
      ${data.coverage ? `<p class="small"><strong>Coverage Info:</strong> ${escapeHtml(data.coverage.unsupported)} technique(s) not supported.</p>` : ""}
    `;
  }

  const title = data.state === "unsupported"
    ? "No CALDERA operation created."
    : "Operation completed.";
  const message = data.state === "unsupported"
    ? `<p class="small">${escapeHtml(data.message || "Unsupported techniques require external validation.")}</p>`
    : "";

  return `
    <p><strong>${title}</strong></p>
    ${message}
    ${renderStatusRows([
      ["Target", escapeHtml(data.target || "Unknown")],
      ["Target source", escapeHtml(data.target_source || "Unknown")],
      ["Original external target", escapeHtml(data.external_target || "Unknown")],
      ["Operation ID", escapeHtml(data.operation_id || "-")],
      ["Operation name", escapeHtml(data.operation_name || "-")],
      ["State", escapeHtml(data.state || "-")],
      ["Agent host", escapeHtml(data.agent_host || "-")],
      ["Agent PAW", escapeHtml(data.agent_paw || "-")],
      ["Total techniques", escapeHtml(data.total ?? "-")],
      ["Successful", escapeHtml(data.success_count ?? "-")],
      ["Failed", escapeHtml(data.fail_count ?? "-")],
      ["Discarded", escapeHtml(data.discarded_count ?? "-")],
      ["Unsupported", escapeHtml(data.unsupported_count ?? "-")]
    ])}
    ${renderProofOfAccessInfo(data.proof_of_access)}
  `;
}

function getEndpoint(name, fallback) {
  return window.DASHBOARD_ENDPOINTS?.[name] || fallback;
}

function getDashboardContext() {
  return window.DASHBOARD_CONTEXT || {
    target: "Unknown",
    portRange: "1-1024",
    selectedMode: "hybrid"
  };
}

function getCsrfToken() {
  return window.DASHBOARD_SECURITY?.csrfToken || "";
}

const originalFetch = window.fetch.bind(window);
window.fetch = (input, init = {}) => {
  const method = String(init.method || "GET").toUpperCase();
  const token = getCsrfToken();
  if (token && !["GET", "HEAD", "OPTIONS"].includes(method)) {
    const headers = new Headers(init.headers || {});
    headers.set("X-CSRF-Token", token);
    return originalFetch(input, {...init, headers});
  }
  return originalFetch(input, init);
};

window.addEventListener("DOMContentLoaded", () => {
  if (typeof applyModeBehavior === "function") {
    applyModeBehavior();
  }

  loadCalderaStatus();

  document.getElementById("runCalderaBtn")
    ?.addEventListener("click", runCaldera);

  document.getElementById("runValidationBtn")
    ?.addEventListener("click", runExploitabilityValidation);

  document.getElementById("generateAdviceBtn")
    ?.addEventListener("click", generatePentestAdvice);

  document.getElementById("refreshMetasploitBtn")
    ?.addEventListener("click", loadMetasploitStatus);

  document.getElementById("loadMetasploitActionsBtn")
    ?.addEventListener("click", loadMetasploitActions);

  document.querySelectorAll("[data-msf-cleanup]").forEach(button => {
    button.addEventListener("click", () => cleanupMetasploitRun(button));
  });

  document.getElementById("copyDeployCommandBtn")
    ?.addEventListener("click", copyDeployCommand);

  document.getElementById("refreshAgentStatusBtn")
    ?.addEventListener("click", loadCalderaStatus);

  document.getElementById("generateReportBtn")
    ?.addEventListener("click", generateReport);

  document.getElementById("downloadReportBtn")
    ?.addEventListener("click", downloadReport);

  document.getElementById("viewAllCvesNavBtn")
    ?.addEventListener("click", () => {
      document.getElementById("cve-review")?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
    
  document.getElementById("downloadReportNavBtn")
    ?.addEventListener("click", () => {
      const reportSection = document.getElementById("report");
      if (reportSection) {
        reportSection.scrollIntoView({ behavior: "smooth", block: "start" });
      }
      document.getElementById("generateReportBtn")?.focus();
    });

  if (document.getElementById("metasploitStatusSummary")) {
    loadMetasploitStatus();
  }
});

async function loadCalderaStatus() {
  const box = document.getElementById("calderaStatusBox");
  const deployBox = document.getElementById("deployCommandBox");
  const deployText = document.getElementById("deployCommandText");
  const deployPlatformText =
    document.getElementById("deployPlatformText");
  const deployShellText =
    document.getElementById("deployShellText");
  const deployCommandMessage =
    document.getElementById("deployCommandMessage");
  const agentStatusSummary = document.getElementById("agentStatusSummary");
  const deployTargetText = document.getElementById("deployTargetText");
  const deployOsText = document.getElementById("deployOsText");
  const deployTargetSourceText = document.getElementById("deployTargetSourceText");
  const deployExternalTargetText = document.getElementById("deployExternalTargetText");
  const targetMatchTypeText = document.getElementById("targetMatchTypeText");
  const agentRejectionReasonText = document.getElementById("agentRejectionReasonText");
  const selectedPawText = document.getElementById("selectedPawText");

  if (!box) return;

  box.innerHTML = "<p class='muted'>Refreshing CALDERA agent status...</p>";

  try {
    const res = await fetch(getEndpoint("calderaStatus", "/caldera/status"));
    const data = await res.json();
    const agents = data.agents || data.online_agents || [];
    const trustedName = data.online_agents?.[0]?.host || data.online_agents?.[0]?.hostname || data.online_agents?.[0]?.paw || "-";
    if (deployTargetText) deployTargetText.textContent = data.target || getDashboardContext().target || "Unknown";
    if (deployOsText) deployOsText.textContent = data.target_os || "Unknown";
    if (deployPlatformText) {
    deployPlatformText.textContent =
        data.target_platform || "Unknown";
    }

    if (deployShellText) {
    deployShellText.textContent =
        data.deploy_shell || "None";
    }

    if (deployCommandMessage) {
      deployCommandMessage.textContent =
        data.deploy_message || "";
    }
    if (deployTargetSourceText) deployTargetSourceText.textContent = data.target_source || "Unknown";
    if (deployExternalTargetText) deployExternalTargetText.textContent = data.external_target || "Unknown";
    if (targetMatchTypeText) targetMatchTypeText.textContent = data.target_match_type || (data.target_match_confirmed ? "ip" : "none");
    if (agentRejectionReasonText) agentRejectionReasonText.textContent = data.agent_ready === true ? "-" : (data.rejection_reason || data.message || "-");
    if (selectedPawText) selectedPawText.textContent = data.selected_agent_paw || "-";
    document.getElementById("trustedAgentName").textContent = data.agent_ready === true ? trustedName : "-";
    if (agentStatusSummary) {
      const onlineCount = agents.filter(agent => agent.alive).length;
      agentStatusSummary.textContent = `${onlineCount} online agent(s) observed. Target checked: ${data.target || getDashboardContext().target || "Unknown"}.`;
    }

    box.innerHTML = renderCalderaStatus(data);

    if (data.agent_ready === true) {
      if (deployBox) deployBox.style.display = "none";
    }

    else {
      box.innerHTML =
        `<p><strong>Not Ready</strong> - ${escapeHtml(data.message || "Caldera reachable - no trusted agent available")}</p>`;

      if (deployBox) {
    deployBox.style.display = "block";
}

      if (deployText) {
        if (data.deploy_supported && data.deploy_command) {
          deployText.textContent = data.deploy_command;
         } else {
         deployText.textContent =
            data.deploy_message ||
            "No automatic deployment command available.";
    }
}
    }
  }

  catch (e) {
    box.innerHTML =
      '<p class="muted">Unable to reach CALDERA status endpoint. Check CALDERA_URL, CALDERA_API_KEY, and that CALDERA is running.</p>';
  }
}

async function loadDeployCommand() {
  const deployBox = document.getElementById("deployCommandBox");
  const deployText = document.getElementById("deployCommandText");
  const deployTargetText = document.getElementById("deployTargetText");
  const deployOsText = document.getElementById("deployOsText");

  if (!deployBox || !deployText) return;

  deployText.textContent = "Generating deployment command...";
  deployBox.style.display = "block";

  try {
    const res = await fetch(getEndpoint("calderaDeployCommand", "/caldera/deploy-command"));
    const data = await res.json();
    deployText.textContent = data.deploy_command || "Deployment command unavailable.";
    if (deployTargetText) deployTargetText.textContent = data.target || "Unknown";
    if (deployOsText) deployOsText.textContent = data.os || "Unknown";
  }
  catch (err) {
    deployText.textContent = "Could not generate deployment command.";
  }
}

async function copyDeployCommand() {
  const deployText = document.getElementById("deployCommandText");
  if (!deployText || !deployText.textContent) return;

  try {
    await navigator.clipboard.writeText(deployText.textContent);
  }
  catch (err) {
    const range = document.createRange();
    range.selectNodeContents(deployText);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  }
}

async function runExploitabilityValidation() {
  const tbody = document.getElementById("validationResultsBody");
  const narrative = document.getElementById("validationNarrative");

  if (!tbody) return;

  tbody.innerHTML =
    `<tr>
      <td colspan="6" class="small">Running lab-safe validation checks...</td>
    </tr>`;

  try {
    const res = await fetch(getEndpoint("exploitationRun", "/exploitation/run"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({})
    });

    const data = await res.json();

    if (!data.ok) {
      tbody.innerHTML =
        `<tr>
          <td colspan="6" class="small">${escapeHtml(data.error || "Validation failed.")}</td>
        </tr>`;
      return;
    }

    document.getElementById("validationConfirmed").textContent = data.confirmed || 0;
    document.getElementById("validationPotential").textContent = data.potential || 0;
    document.getElementById("validationTotal").textContent = data.total_checked || 0;
    const qConfirmed = document.getElementById("validationQuickConfirmed");
    const qPotential = document.getElementById("validationQuickPotential");
    const qTotal = document.getElementById("validationQuickTotal");
    if (qConfirmed) qConfirmed.textContent = data.confirmed || 0;
    if (qPotential) qPotential.textContent = data.potential || 0;
    if (qTotal) qTotal.textContent = data.total_checked || 0;
    document.getElementById("flowValidation")?.classList.add("complete");

    if (narrative) {
      narrative.textContent = data.narrative || "Validation completed.";
    }

    if (data.findings && data.findings.length) {
      tbody.innerHTML = data.findings.map(item => `
        <tr>
          <td><span class="state ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span></td>
          <td>${escapeHtml(item.service)}</td>
          <td class="mono">${escapeHtml(item.port)}</td>
          <td>${escapeHtml(item.title)}</td>
          <td class="small">${escapeHtml(item.evidence)}</td>
          <td class="small">${escapeHtml(item.next_step)}</td>
        </tr>
      `).join("");
    }

    else {
      tbody.innerHTML =
        `<tr>
          <td colspan="6" class="small">
            No allowlisted validation checks matched the current scan.
          </td>
        </tr>`;
    }
  }

  catch (err) {
    tbody.innerHTML =
      `<tr>
        <td colspan="6" class="small">Could not run validation checks.</td>
      </tr>`;
  }
}

async function generatePentestAdvice() {
  const tbody = document.getElementById("attackAdviceBody");
  const summary = document.getElementById("attackAdviceSummary");

  if (!tbody) return;

  tbody.innerHTML =
    `<tr>
      <td colspan="6" class="small">Generating Ollama attack-path advice...</td>
    </tr>`;

  try {
    const res = await fetch(getEndpoint("pentestAdvice", "/pentest/advice"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({})
    });

    const data = await res.json();

    if (!data.ok) {
      tbody.innerHTML =
        `<tr>
          <td colspan="6" class="small">${escapeHtml(data.error || "Attack-path advice failed.")}</td>
        </tr>`;
      return;
    }

    if (summary) {
      summary.textContent = data.summary || "Attack-path advice generated.";
    }

    if (data.attack_paths && data.attack_paths.length) {
      tbody.innerHTML = data.attack_paths.map(path => `
        <tr>
          <td><span class="state ${escapeHtml(path.confidence)}">${escapeHtml(path.confidence)}</span></td>
          <td>${escapeHtml(path.service)}</td>
          <td class="mono">${escapeHtml(path.port || "N/A")}</td>
          <td class="mono small">${escapeHtml((path.technique_ids || []).join(", "))}</td>
          <td>${escapeHtml(path.recommended_validation)}</td>
          <td class="small">
            <strong>${escapeHtml(path.title)}</strong><br>
            ${escapeHtml(path.reasoning)}<br>
            <span class="muted">${escapeHtml(path.next_step)}</span>
          </td>
        </tr>
      `).join("");
    }

    else {
      tbody.innerHTML =
        `<tr>
          <td colspan="6" class="small">No safe attack-path advice could be generated from the current evidence.</td>
        </tr>`;
    }
  }

  catch (err) {
    tbody.innerHTML =
      `<tr>
        <td colspan="6" class="small">Could not generate attack-path advice.</td>
      </tr>`;
  }
}

async function loadMetasploitStatus() {
  const summary = document.getElementById("metasploitStatusSummary");
  if (!summary) return;

  summary.textContent = "Checking Metasploit RPC...";

  try {
    const res = await fetch(getEndpoint("metasploitStatus", "/pentest/metasploit/status"));
    const data = await res.json();

    if (!data.enabled) {
      summary.textContent = data.message || data.error || "Metasploit RPC integration is disabled.";
      return;
    }

    if (data.available) {
      const version = data.version?.version || data.version?.ruby || "reachable";
      summary.textContent = `Metasploit RPC available (${version}).`;
      return;
    }

    summary.textContent = data.error || "Metasploit RPC is not reachable.";
  }
  catch (err) {
    summary.textContent = "Could not check Metasploit RPC.";
  }
}

async function loadMetasploitActions() {
  const tbody = document.getElementById("metasploitActionsBody");
  const summary = document.getElementById("metasploitStatusSummary");
  if (!tbody) return;

  tbody.innerHTML =
    `<tr>
      <td colspan="6" class="small">Loading allowlisted Metasploit actions...</td>
    </tr>`;

  try {
    const res = await fetch(getEndpoint("metasploitPropose", "/pentest/metasploit/propose"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({})
    });
    const data = await res.json();

    if (!data.ok) {
      tbody.innerHTML =
        `<tr>
          <td colspan="6" class="small">${escapeHtml(data.error || "Could not load Metasploit actions.")}</td>
        </tr>`;
      return;
    }

    if (summary && data.status) {
      if (data.status.available) {
        summary.textContent = "Metasploit RPC available.";
      } else {
        summary.textContent = data.status.message || data.status.error || "Metasploit RPC is not available.";
      }
    }

    renderMetasploitActions(data.actions || []);
  }
  catch (err) {
    tbody.innerHTML =
      `<tr>
        <td colspan="6" class="small">Could not load Metasploit actions.</td>
      </tr>`;
  }
}

function renderMetasploitActions(actions) {
  const tbody = document.getElementById("metasploitActionsBody");
  if (!tbody) return;

  if (!actions.length) {
    tbody.innerHTML =
      `<tr>
        <td colspan="6" class="small">No allowlisted Metasploit action matched the current scan.</td>
      </tr>`;
    return;
  }

  tbody.innerHTML = actions.map(action => `
    <tr>
      <td>
        <strong>${escapeHtml(action.title)}</strong><br>
        <span class="small muted">${escapeHtml(action.reason)}</span>
      </td>
      <td class="mono small">${escapeHtml(action.module_type)}/${escapeHtml(action.module_name)}</td>
      <td class="mono">${escapeHtml(action.target)}:${escapeHtml(action.port)}</td>
      <td><span class="state ${escapeHtml(action.risk)}">${escapeHtml(action.risk)}</span></td>
      <td>${escapeHtml(action.source)}</td>
      <td>
        <button
          class="button secondary"
          type="button"
          data-msf-action="${escapeHtml(action.action_id)}"
          data-msf-approval="${action.requires_approval ? "true" : "false"}">
          Run
        </button>
      </td>
    </tr>
  `).join("");

  tbody.querySelectorAll("[data-msf-action]").forEach(button => {
    button.addEventListener("click", () => runMetasploitAction(button));
  });
}

async function runMetasploitAction(button) {
  const actionId = button.dataset.msfAction;
  const approvalRequired = button.dataset.msfApproval === "true";
  const summary = document.getElementById("metasploitStatusSummary");
  if (!actionId) return;

  let approved = false;
  if (approvalRequired) {
    approved = window.confirm("Approve this Metasploit action for the authorised lab target?");
    if (!approved) return;
  }

  button.disabled = true;
  const previousText = button.textContent;
  button.textContent = "Running";
  if (summary) summary.textContent = "Submitting Metasploit action...";

  try {
    const res = await fetch(getEndpoint("metasploitRun", "/pentest/metasploit/run"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        action_id: actionId,
        approved
      })
    });
    const data = await res.json();

    if (!data.ok) {
      if (summary) summary.textContent = data.error || "Metasploit action was rejected.";
      button.disabled = false;
      button.textContent = previousText;
      return;
    }

    if (summary) summary.textContent = data.summary || "Metasploit action submitted.";
    appendMetasploitRun(data);
    button.textContent = metasploitRunLabel(data);
  }
  catch (err) {
    if (summary) summary.textContent = "Metasploit action failed.";
    button.disabled = false;
    button.textContent = previousText;
  }
}

function appendMetasploitRun(run) {
  const visual = document.getElementById("metasploitVisualResults");
  const actionForCard = run.action || {};
  if (visual) {
    const state = run.session_created ? "Session opened" : metasploitRunLabel(run);
    visual.querySelector(".muted")?.remove();
    visual.insertAdjacentHTML("afterbegin", `
      <article class="msf-result-card">
        <div class="msf-result-head"><span class="state ${run.session_created || run.validation_outcome === 'vulnerable' ? 'confirmed' : 'potential'}">${escapeHtml(state)}</span><time>${escapeHtml(run.timestamp || 'Now')}</time></div>
        <h3>${escapeHtml(actionForCard.title || actionForCard.module_name || 'Metasploit action')}</h3>
        <p class="mono">${escapeHtml(actionForCard.target || '-')}:${escapeHtml(actionForCard.port || '-')}</p>
        <p><strong>Outcome:</strong> ${escapeHtml(run.evidence_summary || run.summary || 'Action completed.')}</p>
        <p><strong>Access gained:</strong> ${run.session_created ? 'Yes — target-verified session opened' : 'No — safe check or no session opened'}</p>
        <p><strong>Next step:</strong> ${run.validation_outcome === 'vulnerable' && !run.session_created ? 'Approve the matching controlled exploit action if it is in scope.' : (run.session_created ? 'Continue with authorised CALDERA post-exploitation.' : 'Review evidence; do not claim exploitation success.')}</p>
        ${(run.evidence_items || []).length ? `<ul class="msf-evidence-list">${run.evidence_items.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>` : ''}
        <details><summary>Technical module name</summary><code>${escapeHtml(actionForCard.module_type || '-')}/${escapeHtml(actionForCard.module_name || '-')}</code></details>
      </article>`);
  }
  document.getElementById("flowExploitation")?.classList.add("complete");
  const tbody = document.getElementById("metasploitRunsBody");
  if (!tbody) return;

  const action = run.action || {};
  const cleanupButton = run.session_created && !run.session_closed && run.run_id
    ? `<button class="button secondary" type="button" data-msf-cleanup="${escapeHtml(run.run_id)}">Close session</button>`
    : "-";
  const row = `
    <tr>
      <td class="mono small">${escapeHtml(run.timestamp || "-")}</td>
      <td class="mono small">${escapeHtml(action.module_type || "-")}/${escapeHtml(action.module_name || "-")}</td>
      <td class="mono">${escapeHtml(action.target || "-")}:${escapeHtml(action.port || "-")}</td>
      <td class="small"><strong>${escapeHtml(metasploitRunLabel(run))}</strong><br>${escapeHtml(run.summary || "Metasploit action completed.")}</td>
      <td>${cleanupButton}</td>
    </tr>
  `;

  const placeholder = tbody.querySelector("td[colspan]");
  if (placeholder) {
    tbody.innerHTML = row;
  } else {
    tbody.insertAdjacentHTML("beforeend", row);
  }
  const cleanup = tbody.querySelector(`[data-msf-cleanup="${CSS.escape(run.run_id || "")}"]`);
  if (cleanup) cleanup.addEventListener("click", () => cleanupMetasploitRun(cleanup));
}

function metasploitRunLabel(run) {
  if (run.execution_state === "session_closed" || run.session_closed) return "Session closed";
  if (run.session_created) return "Session opened";
  if (run.action && run.action.module_type === "exploit" && run.module_completed) {
    return "Exploit completed — no session";
  }
  if (run.execution_state === "errored") return "Execution failed";
  if (run.validation_outcome === "vulnerable") return "Vulnerable";
  if (run.validation_outcome === "not_vulnerable") return "Not vulnerable";
  if (run.module_completed) return "Check completed";
  return run.execution_state === "submitted" ? "Submitted" : "Running";
}

async function cleanupMetasploitRun(button) {
  const runId = button.dataset.msfCleanup;
  const summary = document.getElementById("metasploitStatusSummary");
  if (!runId || !window.confirm("Close this target-verified RPC session and stop its remaining job?")) return;

  button.disabled = true;
  button.textContent = "Closing";
  try {
    const res = await fetch(`/pentest/metasploit/run/${encodeURIComponent(runId)}/cleanup`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({approved: true})
    });
    const data = await res.json();
    if (!data.ok) {
      button.disabled = false;
      button.textContent = "Retry cleanup";
      if (summary) summary.textContent = data.error || "Session cleanup failed.";
      return;
    }
    button.textContent = "Session closed";
    if (summary) summary.textContent = data.record?.summary || "RPC session closed. Revert the target snapshot when ready.";
  } catch (err) {
    button.disabled = false;
    button.textContent = "Retry cleanup";
    if (summary) summary.textContent = "Session cleanup failed.";
  }
}

async function runCaldera() {
  const operationBox = document.getElementById("operationBox");
  const selected = typeof getSelectedTechniqueIds === "function"
    ? getSelectedTechniqueIds()
    : [];

  if (!operationBox) return;

  if (!selected.length) {
    operationBox.innerHTML =
      "<p><strong>No techniques selected.</strong></p>";

    return;
  }

  const approved = window.confirm(
    "Approve this CALDERA operation for the selected authorised lab target?"
  );

  if (!approved) {
    operationBox.innerHTML =
      "<p class='muted'>Operation cancelled by operator.</p>";
    return;
  }

  operationBox.innerHTML =
    "<p class='muted'>Starting Caldera operation...</p>";

  try {
    const res = await fetch(getEndpoint("calderaRun", "/caldera/run"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        selected_techniques: selected,
        approved: true
      })
    });

    const data = await res.json();

    // Handle coverage warnings
    const coverageWarningBox = document.getElementById("coverageWarningBox");
    const coverageWarningText = document.getElementById("coverageWarningText");
    if (data.coverage_info) {
      const { unsupported_count, unsupported, supported } = data.coverage_info;
      if (unsupported_count > 0) {
        if (coverageWarningBox && coverageWarningText) {
          coverageWarningText.textContent =
            `${unsupported_count} technique(s) not supported by CALDERA (${unsupported.join(", ")}). ` +
            `${supported.length ? `Executing only ${supported.length} supported technique(s).` : "Recording external validation requirement."}`;
          coverageWarningBox.style.display = "block";
        }
      }
    }

    if (data.ok || data.success) {
      operationBox.innerHTML = renderOperationSummary(data);

      const tbody = document.getElementById("techniqueResultsBody");
      const executionSummary = document.getElementById("executionSummary");

      if (tbody && data.techniques_run && data.techniques_run.length > 0) {
        tbody.innerHTML = data.techniques_run.map(t => `
          <tr>
            <td class="mono">${escapeHtml(t.technique_id)}</td>
            <td>${escapeHtml(t.technique_name)}</td>
            <td>${escapeHtml(t.tactic)}</td>
            <td><strong>${escapeHtml(t.status)}</strong></td>
            <td class="small">${escapeHtml(t.timestamp || "-")}</td>
            <td class="small">
              <div class="caldera-readable-result">
                <strong>${escapeHtml(t.evidence_summary || (t.status === 'success' ? 'Technique completed successfully.' : 'Technique did not produce confirmed evidence.'))}</strong>
                ${formatEvidenceList(t.parsed_evidence)}
                <details>
                  <summary>Technical command and raw output</summary>
                  <p><strong>Command executed</strong></p>
                  <pre class="small mono">${escapeHtml(t.command || "No command returned by CALDERA.")}</pre>
                  <p><strong>Raw stdout</strong></p>
                  <pre class="small mono">${escapeHtml(t.stdout || t.output || "Execution completed but no evidence returned.")}</pre>
                  ${t.stderr ? `<p><strong>Raw stderr</strong></p><pre class="small mono">${escapeHtml(t.stderr)}</pre>` : ""}
                </details>
              </div>
            </td>
          </tr>
        `).join("");

        // Update execution summary
        if (executionSummary) {
          const total = data.total || data.techniques_run.length;
          const successful = data.success_count || 0;
          const failed = data.fail_count || 0;
          const discarded = data.discarded_count || 0;

          document.getElementById("totalTechniques").textContent = total;
          document.getElementById("successfulTechniques").textContent = successful;
          document.getElementById("failedTechniques").textContent = failed;
          document.getElementById("discardedTechniques").textContent = discarded;
          executionSummary.style.display = "grid";
        }
        // refresh agent status after operation completes
        try { loadCalderaStatus(); } catch(e) {}
      }

      else if (tbody) {
        tbody.innerHTML =
          `<tr>
            <td colspan="6" class="small">
              No execution results returned.
            </td>
          </tr>`;
      }

      if (data.risk) {
        document.getElementById("riskScoreValue").textContent =
          data.risk.score ?? "N/A";

        document.getElementById("riskLabelValue").textContent =
          data.risk.label ?? "N/A";

        document.getElementById("riskColourValue").textContent =
          data.risk.colour ?? "N/A";

        document.getElementById("riskBadgeValue").textContent =
          data.risk.badge ?? "N/A";
      }
    }

    else {
      operationBox.innerHTML = renderOperationSummary(data);
    }
  }

  catch (err) {
    operationBox.innerHTML =
      `<p><strong>Error starting operation.</strong></p><p class="small">${escapeHtml(err.message || "Check the Flask terminal for details.")}</p>`;
  }
}

async function refreshOperationStatus() {
  const operationBox = document.getElementById("operationBox");

  if (!operationBox) return;

  try {
    const res = await fetch(getEndpoint("operationStatus", "/caldera/operation/status"));
    const data = await res.json();

    operationBox.innerHTML = renderOperationSummary(data);
  }

  catch (e) {
    operationBox.innerHTML =
      "<p class='muted'>Could not refresh operation status.</p>";
  }
}

async function generateReport() {
  const reportBox = document.getElementById("reportBox");
  const downloadBtn = document.getElementById("downloadReportBtn");

  if (!reportBox || !downloadBtn) return;

  const selectedTechniques = typeof getSelectedTechniqueIds === "function"
    ? getSelectedTechniqueIds()
    : [];

  const executionText = getExecutionRowsAsText();
  const validationText = getValidationRowsAsText();
  const context = getDashboardContext();

  reportBox.innerHTML = "<p class='muted'>Generating report...</p>";

  const reportData = {
    target: context.target || "Unknown",
    port_range: context.portRange || "1-1024",
    selected_mode: context.selectedMode || "hybrid",
    risk_score: document.getElementById("riskScoreValue")?.innerText || "N/A",
    risk_label: document.getElementById("riskLabelValue")?.innerText || "N/A",
    selected_techniques: selectedTechniques,
    validation_results: validationText,
    execution_results: executionText
  };

  try {
    const res = await fetch(getEndpoint("generateReport", "/generate_report"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(reportData)
    });

    const data = await res.json();
    if (!res.ok || !data || (!data.report && !data.summary)) {
      throw new Error(data?.error || "Report generation failed.");
    }

    generatedReportContent = data.report || data.summary || "";
    window.location.href = data.report_url || getEndpoint("reportView", "/report/view");
    return;
  }

  catch (err) {
    generatedReportContent = "";
    reportBox.innerHTML =
      `<p class="muted">Unable to generate report. ${escapeHtml(err.message || "Please try again.")}</p>`;
    downloadBtn.disabled = true;
  }
}

function downloadReport() {
  const exportUrl = getEndpoint("reportExport", "/report/export");
  if (exportUrl) {
    window.location.href = exportUrl;
    return;
  }

  if (!generatedReportContent) return;

  const blob = new Blob([generatedReportContent], {
    type: "text/plain;charset=utf-8"
  });

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");

  a.href = url;
  a.download = "autopentest_report.txt";
  document.body.appendChild(a);
  a.click();

  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function getSmbTarget() {
  const ctx = typeof getDashboardContext === "function"
    ? getDashboardContext()
    : window.DASHBOARD_CONTEXT;

  return ctx?.target || "";
}

async function smbApiPost(path, body = {}) {
  const csrf = window.DASHBOARD_SECURITY?.csrfToken || "";

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(csrf ? { "X-CSRF-Token": csrf } : {}),
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    const responseText = await response.text();

    let data;

    try {
      data = responseText ? JSON.parse(responseText) : {};
    } catch {
      throw new Error(
        `Server returned ${response.status} instead of JSON: ` +
        responseText.substring(0, 150)
      );
    }

    if (!response.ok) {
      throw new Error(
        data.error || `Request failed with status ${response.status}`
      );
    }

    return data;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error("SMB request timed out after 15 seconds.");
    }

    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

function showSmbResults() {
  document.getElementById("smbResults").style.display = "block";
  document.getElementById("smbFingerprintBtn").style.display = "";
  document.getElementById("smbHydraBtn").style.display = "";
  document.getElementById("smbFileOpsBtn").style.display = "";
  document.getElementById("smbChainBtn").style.display = "";
}


// ── PROPOSE ──
document
  .getElementById("smbProposeBtn")
  ?.addEventListener("click", async () => {
    const list = document.getElementById("smbActionsList");
    const target = getSmbTarget();

    if (!list) {
      return;
    }

    if (!target) {
      list.innerHTML =
        "<p class='muted'>No target in scan context. Run a scan first.</p>";
      return;
    }

    list.innerHTML =
      "<p class='muted'>Checking scan results for SMB services...</p>";

    try {
      const data = await smbApiPost("/pentest/smb/propose");

      if (!data.ok || !data.actions?.length) {
        list.innerHTML = `
          <p class="muted">
            ${escapeHtml(
              data.error ||
              "No SMB service detected. Ensure port 139 or 445 is open."
            )}
          </p>
        `;
        return;
      }

      showSmbResults();

      list.innerHTML = data.actions
        .map((action) => `
          <div
            class="action-card"
            style="
              padding: 8px;
              margin: 4px 0;
              border-left: 3px solid ${
                action.risk === "high"
                  ? "red"
                  : action.risk === "medium"
                    ? "orange"
                    : "#4a9"
              };
              background: #1e1e1e;
            "
          >
            <strong>${escapeHtml(action.title)}</strong>

            <span class="state ${escapeHtml(action.risk)}">
              ${escapeHtml((action.risk || "info").toUpperCase())}
            </span>

            <p class="small muted">
              ${escapeHtml(action.description)}
            </p>
          </div>
        `)
        .join("");

      window._smbActions = data.actions;
    } catch (error) {
      console.error("SMB proposal request failed:", error);

      list.innerHTML = `
        <p class="bad">
          SMB request failed: ${escapeHtml(error.message)}
        </p>
      `;
    }
  });


// ── FINGERPRINT ──
document
  .getElementById("smbFingerprintBtn")
  ?.addEventListener("click", async () => {
    const pre = document.getElementById("smbFingerprintOutput");

    pre.textContent = "Running nmap SMB scripts...";

    const data = await smbApiPost("/pentest/smb/fingerprint", {
      target: getSmbTarget(),
    });

    showSmbResults();

    pre.textContent =
      data.raw_output || JSON.stringify(data, null, 2);

    if (data.port_open === false) {
      pre.textContent +=
        "\n\n[!] PORT 445 IS CLOSED — SMB exploitation not possible.";
    }
  });


// ── HYDRA ──
document.getElementById("smbHydraBtn")?.addEventListener("click", async () => {
  const pre = document.getElementById("smbHydraOutput");

  pre.textContent = "Running Hydra against smb2:// ...";

  const data = await smbApiPost("/pentest/smb/hydra", {
    target: getSmbTarget(),
  });

  showSmbResults();

  pre.textContent =
    data.raw_output || JSON.stringify(data, null, 2);

  const credDiv = document.getElementById("smbCredentialsFound");
  const credSpan = document.getElementById("smbCredsDisplay");

  if (data.password_found) {
    credDiv.style.display = "block";
    credSpan.style.color = "";

    credSpan.textContent =
      `${data.username || "smbtest"} : ${data.password_found}`;

    window._smbPassword = data.password_found;
    window._smbUsername = data.username || "smbtest";
  } else {
    credDiv.style.display = "block";
    credSpan.textContent = "No credentials found.";
    credSpan.style.color = "red";
  }
});


// ── FILE OPERATIONS ──
document
  .getElementById("smbFileOpsBtn")
  ?.addEventListener("click", async () => {
    const password =
      window._smbPassword || prompt("Enter SMB password:");

    if (!password) {
      return;
    }

    const username = window._smbUsername || "smbtest";

    document.getElementById("smbBeforeFiles").textContent = "Running...";
    document.getElementById("smbAfterFiles").textContent = "...";

    const data = await smbApiPost("/pentest/smb/file-ops", {
      target: getSmbTarget(),
      username,
      password,
    });

    showSmbResults();

    document.getElementById("smbBeforeFiles").textContent =
      data.before_raw ||
      data.before_files?.join("\n") ||
      "(no files)";

    document.getElementById("smbAfterFiles").textContent =
      data.after_raw ||
      data.after_files?.join("\n") ||
      "(no files)";

    document.getElementById("smbOpsTableBody").innerHTML =
      (data.operations || []).map((operation) => `
        <tr>
          <td>
            <strong>${escapeHtml(operation.action)}</strong>
          </td>

          <td class="mono">
            ${escapeHtml(operation.file)}
          </td>

          <td>
            <span class="state ${
              operation.success ? "confirmed" : "failed"
            }">
              ${operation.success ? "OK" : "FAIL"}
            </span>
          </td>

          <td class="small">
            ${escapeHtml(
              operation.output ||
              (
                operation.original_preview
                  ? "Original: " +
                    operation.original_preview.substring(0, 60) +
                    "..."
                  : ""
              )
            )}
          </td>
        </tr>
      `).join("");

    document.getElementById("smbSummary").textContent =
      data.summary || "";
  });


// ── FULL CHAIN ──
let _smbChainPollTimer = null;

document.getElementById("smbChainBtn")?.addEventListener("click", async () => {
  const password =
    window._smbPassword ||
    prompt("Enter SMB password (or leave blank for Hydra):") ||
    "";

  const username =
    window._smbUsername || "smbtest";

  const progress =
    document.getElementById("smbChainProgress");

  progress.style.display = "block";

  document.getElementById("smbChainStatus").textContent =
    "starting...";

  document.getElementById("smbChainSteps").innerHTML = "";

  const data = await smbApiPost("/pentest/smb/chain", {
    target: getSmbTarget(),
    username,
    password,
  });

  if (!data.ok || !data.run_id) {
    document.getElementById("smbChainStatus").textContent =
      "Failed to start: " + (data.error || "unknown");
    return;
  }

  if (_smbChainPollTimer) {
    clearInterval(_smbChainPollTimer);
  }

  _smbChainPollTimer = setInterval(async () => {
    const response = await fetch(
      `/pentest/smb/chain/status/${data.run_id}`
    );

    const statusData = await response.json();

    document.getElementById("smbChainStatus").textContent =
      statusData.status || "unknown";

    const stepsDiv =
      document.getElementById("smbChainSteps");

    stepsDiv.innerHTML =
      (statusData.steps || []).map((step) => `
        <div
          style="
            padding: 4px 8px;
            margin: 2px 0;
            background: #1e1e1e;
            border-left: 3px solid ${
              step.status === "success"
                ? "#4a9"
                : step.status === "failed"
                  ? "red"
                  : "orange"
            };
          "
        >
          <strong>${escapeHtml(step.title)}</strong>

          <span class="small">
            [${escapeHtml(step.status)}]
          </span>

          ${
            step.result
              ? `
                <span class="small mono">
                  — ${escapeHtml(step.result)}
                </span>
              `
              : ""
          }

          ${
            step.password_found
              ? `
                <span class="good small">
                  — Password:
                  ${escapeHtml(step.username || "")}:${escapeHtml(
                    step.password_found || step.password || ""
                  )}
                </span>
              `
              : ""
          }

          ${
            step.summary
              ? `
                <p class="small muted">
                  ${escapeHtml(step.summary)}
                </p>
              `
              : ""
          }

          ${
            step.added_files
              ? `
                <p class="small">
                  + Added:
                  ${escapeHtml(
                    step.added_files.join(", ") || "none"
                  )}
                </p>
              `
              : ""
          }

          ${
            step.removed_files
              ? `
                <p class="small">
                  - Removed:
                  ${escapeHtml(
                    step.removed_files.join(", ") || "none"
                  )}
                </p>
              `
              : ""
          }
        </div>
      `).join("") || stepsDiv.innerHTML;

    if (
      statusData.status === "completed" ||
      statusData.status === "failed"
    ) {
      clearInterval(_smbChainPollTimer);
      _smbChainPollTimer = null;

      document.getElementById("smbChainStatus").textContent =
        statusData.status === "completed"
          ? "✓ CHAIN COMPLETE"
          : "✗ CHAIN FAILED";

      const fileOperationsStep =
        (statusData.steps || []).find(
          (step) => step.stage === "file_operations"
        );

      if (fileOperationsStep) {
        document.getElementById("smbBeforeFiles").textContent =
          (fileOperationsStep.before_files || []).join("\n");

        document.getElementById("smbAfterFiles").textContent =
          (fileOperationsStep.after_files || []).join("\n");

        document.getElementById("smbOpsTableBody").innerHTML =
          (fileOperationsStep.operations || []).map((operation) => `
            <tr>
              <td>
                <strong>${escapeHtml(operation.action)}</strong>
              </td>

              <td class="mono">
                ${escapeHtml(operation.file)}
              </td>

              <td>
                <span class="state ${
                  operation.success ? "confirmed" : "failed"
                }">
                  ${operation.success ? "OK" : "FAIL"}
                </span>
              </td>

              <td class="small">
                ${escapeHtml(operation.output || "")}
              </td>
            </tr>
          `).join("");

        document.getElementById("smbSummary").textContent =
          fileOperationsStep.summary || "";

        showSmbResults();
      }
    }
  }, 2000);
});


function escapeHtml(value) {
  if (!value) {
    return "";
  }

  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}


// ── RESULTS WORKSPACE TABS ──
(function initResultsWorkspaceTabs() {
  const tabs = Array.from(
    document.querySelectorAll("[data-dashboard-tab]")
  );

  const panes = Array.from(
    document.querySelectorAll("[data-dashboard-pane]")
  );

  if (!tabs.length || !panes.length) {
    return;
  }

  function activate(name, updateHash = true, shouldScroll = true) {
    const valid = panes.some(
      (pane) => pane.dataset.dashboardPane === name
    );

    const target = valid ? name : "overview";

    tabs.forEach((tab) => {
      const active =
        tab.dataset.dashboardTab === target;

      tab.classList.toggle("is-active", active);
      tab.setAttribute(
        "aria-selected",
        active ? "true" : "false"
      );
    });

    panes.forEach((pane) => {
      pane.classList.toggle(
        "is-active",
        pane.dataset.dashboardPane === target
      );
    });

    if (updateHash) {
      history.replaceState(null, "", `#${target}`);
    }

    const tabBar =
      document.querySelector(".results-tabs");

    if (tabBar && shouldScroll) {
      window.scrollTo({
        top: Math.max(0, tabBar.offsetTop - 100),
        behavior: "smooth",
      });
    }
  }

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      activate(tab.dataset.dashboardTab);
    });
  });

  document
    .querySelectorAll("[data-dashboard-tab-link]")
    .forEach((link) => {
      link.addEventListener("click", (event) => {
        event.preventDefault();
        activate(link.dataset.dashboardTabLink);
      });
    });

  activate(
    (location.hash || "").replace("#", "") || "overview",
    false,
    false
  );
})();


// ── PAGE INITIALISATION ──
document.addEventListener("DOMContentLoaded", function () {
  const pdfBtn =
    document.getElementById("downloadPdfReportBtn");

  if (pdfBtn) {
    pdfBtn.addEventListener("click", function () {
      window.location.href = getEndpoint(
        "reportExportPdf",
        "/report/export/pdf"
      );

      document
        .getElementById("flowReport")
        ?.classList.add("complete");
    });
  }

  const fab =
    document.getElementById("aiFab");

  const drawer =
    document.getElementById("aiChatDrawer");

  const close =
    document.getElementById("aiChatClose");

  const setOpen = (open) => {
    if (!fab || !drawer) {
      return;
    }

    drawer.classList.toggle("is-open", open);

    drawer.setAttribute(
      "aria-hidden",
      open ? "false" : "true"
    );

    fab.setAttribute(
      "aria-expanded",
      open ? "true" : "false"
    );

    if (open) {
      setTimeout(() => {
        document
          .getElementById("aiChatInput")
          ?.focus();
      }, 120);
    }
  };

  fab?.addEventListener("click", () => {
    setOpen(
      !drawer?.classList.contains("is-open")
    );
  });

  close?.addEventListener("click", () => {
    setOpen(false);
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      setOpen(false);
    }
  });

  if (
    document.querySelector(
      "#operationBox .operation-result, #operationBox table"
    )
  ) {
    document
      .getElementById("flowPostExploit")
      ?.classList.add("complete");
  }
});

// ==========================================
// GLOBAL THEME TOGGLE
// ==========================================

(function initThemeToggle() {
  const STORAGE_KEY = "penpilot-theme";

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);

    document.querySelectorAll(".theme-toggle").forEach((button) => {
      const icon = button.querySelector("i");

      if (theme === "light") {
        button.title = "Switch to Dark Mode";
        button.setAttribute("aria-label", "Switch to Dark Mode");

        if (icon) {
          icon.className = "bi bi-moon-fill";
        }
      } else {
        button.title = "Switch to Light Mode";
        button.setAttribute("aria-label", "Switch to Light Mode");

        if (icon) {
          icon.className = "bi bi-sun-fill";
        }
      }
    });
  }

  // Restore saved theme
  const savedTheme =
    localStorage.getItem(STORAGE_KEY) || "dark";

  applyTheme(savedTheme);

  // Handle every navbar theme button
  document.querySelectorAll(".theme-toggle").forEach((button) => {
    button.addEventListener("click", () => {
      const currentTheme =
        document.documentElement.getAttribute("data-theme") || "dark";

      const newTheme =
        currentTheme === "light" ? "dark" : "light";

      localStorage.setItem(STORAGE_KEY, newTheme);
      applyTheme(newTheme);
    });
  });
})();