
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
      if (typeof openCveModal === "function") {
        openCveModal();
      } else {
        window.location.hash = "#scan-vuln";
      }
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
  const agentStatusSummary = document.getElementById("agentStatusSummary");
  const deployTargetText = document.getElementById("deployTargetText");
  const deployOsText = document.getElementById("deployOsText");

  if (!box) return;

  box.innerHTML = "<p class='muted'>Refreshing CALDERA agent status...</p>";

  try {
    const res = await fetch(getEndpoint("calderaStatus", "/caldera/status"));
    const data = await res.json();
    const agents = data.agents || data.online_agents || [];
    const trustedName = data.online_agents?.[0]?.host || data.online_agents?.[0]?.hostname || data.online_agents?.[0]?.paw || "-";
    if (deployTargetText) deployTargetText.textContent = data.target || getDashboardContext().target || "Unknown";
    if (deployOsText) deployOsText.textContent = data.target_os || "Unknown";
    document.getElementById("trustedAgentName").textContent = data.agent_ready ? trustedName : "-";
    if (agentStatusSummary) {
      const onlineCount = agents.filter(agent => agent.alive).length;
      agentStatusSummary.textContent = `${onlineCount} online agent(s) observed. Target checked: ${data.target || getDashboardContext().target || "Unknown"}.`;
    }

    if (data.agent_ready) {
      box.innerHTML =
        data.target_match_confirmed === false
          ? `<p><strong>Ready</strong> - ${data.online_agents?.length || 1} trusted agent(s) online. Confirm the selected agent is the intended target before running.</p>`
          : `<p><strong>Ready</strong> - trusted agent matched.</p>`;
      if (deployBox) deployBox.style.display = "none";
    }

    else {
      box.innerHTML =
        `<p><strong>Not Ready</strong> - ${escapeHtml(data.message || "Caldera reachable - no trusted agent available")}</p>`;

      if (data.deploy_command && deployText && deployBox) {
        deployText.textContent = data.deploy_command;
        deployBox.style.display = "block";
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
      summary.textContent = data.message || "Metasploit RPC integration is disabled.";
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
    button.textContent = "Done";
  }
  catch (err) {
    if (summary) summary.textContent = "Metasploit action failed.";
    button.disabled = false;
    button.textContent = previousText;
  }
}

function appendMetasploitRun(run) {
  const tbody = document.getElementById("metasploitRunsBody");
  if (!tbody) return;

  const action = run.action || {};
  const row = `
    <tr>
      <td class="mono small">${escapeHtml(run.timestamp || "-")}</td>
      <td class="mono small">${escapeHtml(action.module_type || "-")}/${escapeHtml(action.module_name || "-")}</td>
      <td class="mono">${escapeHtml(action.target || "-")}:${escapeHtml(action.port || "-")}</td>
      <td class="small">${escapeHtml(run.summary || "Metasploit action completed.")}</td>
    </tr>
  `;

  const placeholder = tbody.querySelector("td[colspan]");
  if (placeholder) {
    tbody.innerHTML = row;
  } else {
    tbody.insertAdjacentHTML("beforeend", row);
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

  operationBox.innerHTML =
    "<p class='muted'>Starting Caldera operation...</p>";

  try {
    const res = await fetch(getEndpoint("calderaRun", "/caldera/run"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        selected_techniques: selected
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
      operationBox.innerHTML =
        data.state === "unsupported"
          ? `<p><strong>No CALDERA operation created.</strong></p><p class="small">${escapeHtml(data.message || "Unsupported techniques require external validation.")}</p>`
          : `<p><strong>Operation completed.</strong></p>`;

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
              <details>
                <summary>${escapeHtml(t.evidence_summary || "View execution evidence")}</summary>
                <p><strong>Command executed</strong></p>
                <pre class="small mono">${escapeHtml(t.command || "No command returned by CALDERA.")}</pre>
                <p><strong>Parsed evidence</strong></p>
                ${formatEvidenceList(t.parsed_evidence)}
                <p><strong>Raw stdout</strong></p>
                <pre class="small mono">${escapeHtml(t.stdout || t.output || "Execution completed but no evidence returned.")}</pre>
                ${t.stderr ? `<p><strong>Raw stderr</strong></p><pre class="small mono">${escapeHtml(t.stderr)}</pre>` : ""}
              </details>
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
      operationBox.innerHTML =
        `<p><strong>Operation failed.</strong></p>
         <p class="small">${escapeHtml(data.message || data.error || "No error message returned.")}</p>`;

      if (data.coverage) {
        operationBox.innerHTML +=
          `<p class="small"><strong>Coverage Info:</strong> ${data.coverage.unsupported} technique(s) not supported.</p>`;
      }
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

    operationBox.innerHTML =
      `<pre class="small mono">${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
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
