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

  document.getElementById("refreshStatusBtn")
    ?.addEventListener("click", refreshOperationStatus);

  document.getElementById("generateReportBtn")
    ?.addEventListener("click", generateReport);

  document.getElementById("downloadReportBtn")
    ?.addEventListener("click", downloadReport);
});

async function loadCalderaStatus() {
  const box = document.getElementById("calderaStatusBox");
  const deployBox = document.getElementById("deployCommandBox");
  const deployText = document.getElementById("deployCommandText");

  if (!box) return;

  try {
    const res = await fetch(getEndpoint("calderaStatus", "/caldera_status"));
    const data = await res.json();

    if (data.agent_ready) {
      box.innerHTML =
        `<p><strong>Ready</strong> — ${data.online_agents?.length || 1} agent(s) online.</p>`;

      if (deployBox) deployBox.style.display = "none";
    }

    else {
      box.innerHTML =
        `<p><strong>Not Ready</strong> — ${escapeHtml(data.message || "No agent found.")}</p>`;

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
    const res = await fetch(getEndpoint("calderaRun", "/caldera_run"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        selected_techniques: selected
      })
    });

    const data = await res.json();

    if (data.ok || data.success) {
      operationBox.innerHTML =
        `<p><strong>Operation completed successfully.</strong></p>`;

      const tbody = document.getElementById("techniqueResultsBody");

      if (tbody && data.techniques_run && data.techniques_run.length > 0) {
        tbody.innerHTML = data.techniques_run.map(t => `
          <tr>
            <td class="mono">${escapeHtml(t.technique_id)}</td>
            <td>${escapeHtml(t.technique_name)}</td>
            <td>${escapeHtml(t.tactic)}</td>
            <td>${escapeHtml(t.status)}</td>
            <td>${escapeHtml(t.timestamp || "-")}</td>
            <td class="small">${escapeHtml(t.output || "-")}</td>
          </tr>
        `).join("");
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
         <p class="small">${escapeHtml(data.message || "No error message returned.")}</p>`;
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
    const res = await fetch(getEndpoint("operationStatus", "/operation_status"));
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
  const context = getDashboardContext();

  reportBox.innerHTML = "<p class='muted'>Generating report...</p>";

  const reportData = {
    target: context.target || "Unknown",
    port_range: context.portRange || "1-1024",
    selected_mode: context.selectedMode || "hybrid",
    risk_score: document.getElementById("riskScoreValue")?.innerText || "N/A",
    risk_label: document.getElementById("riskLabelValue")?.innerText || "N/A",
    selected_techniques: selectedTechniques,
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

    if (res.ok) {
      const data = await res.json();

      generatedReportContent =
        data.report ||
        data.summary ||
        buildLocalReport(reportData);

      reportBox.innerHTML =
        `<pre class="report-preview">${escapeHtml(generatedReportContent)}</pre>`;

      downloadBtn.disabled = false;
      return;
    }
  }

  catch (err) {
    // Fallback below if backend route does not exist yet.
  }

  generatedReportContent = buildLocalReport(reportData);

  reportBox.innerHTML =
    `<pre class="report-preview">${escapeHtml(generatedReportContent)}</pre>
     <p class="small top-gap">
       Backend /generate_report route was not found, so a local browser report was generated instead.
     </p>`;

  downloadBtn.disabled = false;
}

function buildLocalReport(data) {
  return `
AI-Assisted Penetration Testing Report

Target:
${data.target}

Port Range:
${data.port_range}

Technique Mode:
${data.selected_mode.toUpperCase()}

Risk Summary:
Score: ${data.risk_score}
Label: ${data.risk_label}

Selected MITRE ATT&CK Techniques:
${data.selected_techniques.length ? data.selected_techniques.join(", ") : "No selected techniques."}

Execution Results:
${data.execution_results || "No execution results generated yet."}

Summary:
The scan findings and vulnerability mapping were reviewed together with the selected technique mode. The selected MITRE ATT&CK techniques were prepared for Caldera execution. The execution results above should be used to validate exposure, document findings, and support remediation planning.
  `.trim();
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