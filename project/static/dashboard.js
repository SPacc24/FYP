
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

window.addEventListener("DOMContentLoaded", () => {
  if (typeof applyModeBehavior === "function") {
    applyModeBehavior();
  }

  loadCalderaStatus();

  document.getElementById("runCalderaBtn")
    ?.addEventListener("click", runCaldera);

  document.getElementById("runValidationBtn")
    ?.addEventListener("click", runExploitabilityValidation);

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
        `<p><strong>Ready</strong> - trusted agent matched.</p>`;
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
      '<p class="muted">Unable to reach Caldera status endpoint.</p>';
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
      "<p><strong>Error starting operation.</strong></p>";
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
    reportBox.innerHTML =
      `<pre class="report-preview">${escapeHtml(generatedReportContent || "No report content returned.")}</pre>`;

    downloadBtn.disabled = !generatedReportContent;
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
