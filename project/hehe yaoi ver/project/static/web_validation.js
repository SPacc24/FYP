window.addEventListener("DOMContentLoaded", () => {
  document.getElementById("loadWebValidationActionsBtn")
    ?.addEventListener("click", loadWebValidationActions);
});

function webValidationStateClass(status) {
  if (status === "confirmed") return "confirmed";
  if (status === "not_confirmed") return "potential";
  return "failed";
}

async function loadWebValidationActions() {
  const tbody = document.getElementById("webValidationActionsBody");
  const summary = document.getElementById("webValidationSummaryText");

  if (!tbody) return;

  tbody.innerHTML = `
    <tr>
      <td colspan="5" class="small">
        Loading allowlisted web-validation actions...
      </td>
    </tr>
  `;

  try {
    const response = await fetch(
      getEndpoint(
        "webValidationPropose",
        "/pentest/web-validation/propose"
      ),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({})
      }
    );

    const data = await response.json();

    if (!response.ok || !data.ok) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5" class="small">
            ${escapeHtml(
              data.error || "Could not load web-validation actions."
            )}
          </td>
        </tr>
      `;
      return;
    }

    if (summary) {
      summary.textContent =
        data.reason ||
        `${data.count || 0} allowlisted action(s) matched the current scan.`;
    }

    renderWebValidationActions(data.actions || []);
  } catch (error) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="small">
          Could not load web-validation actions.
        </td>
      </tr>
    `;
  }
}

function renderWebValidationActions(actions) {
  const tbody = document.getElementById("webValidationActionsBody");

  if (!tbody) return;

  if (!actions.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="small">
          No private lab target matched the complete allowlisted fingerprint.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = actions.map(action => {
    const approvalId = `approve_${action.action_id}`;
    const sources = (action.evidence_sources || []).join(", ");

    return `
      <tr>
        <td>
          <strong>${escapeHtml(action.title)}</strong><br>

          <span class="small muted">
            ${escapeHtml(action.reason)}
          </span><br>

          <span class="state ${escapeHtml(action.risk)}">
            ${escapeHtml(action.risk)}
          </span>
        </td>

        <td class="mono">
          ${escapeHtml(action.target)}:${escapeHtml(action.port)}
        </td>

        <td class="mono small">
          ${escapeHtml(action.method)}
          ${escapeHtml(action.endpoint)}<br>

          Parameter: ${escapeHtml(action.parameter)}
        </td>

        <td class="small">
          ${escapeHtml(sources || "Current scan evidence")}
        </td>

        <td>
          <label class="small" for="${escapeHtml(approvalId)}">
            <input
              id="${escapeHtml(approvalId)}"
              type="checkbox"
              data-web-approval="${escapeHtml(action.action_id)}">

            I approve this authorised lab validation.
          </label>

          <br>

          <button
            class="button secondary top-gap"
            type="button"
            data-web-action="${escapeHtml(action.action_id)}"
            disabled>
            Run
          </button>
        </td>
      </tr>
    `;
  }).join("");

  tbody.querySelectorAll("[data-web-approval]").forEach(checkbox => {
    checkbox.addEventListener("change", () => {
      const actionId = checkbox.dataset.webApproval;

      const button = tbody.querySelector(
        `[data-web-action="${CSS.escape(actionId)}"]`
      );

      if (button) {
        button.disabled = !checkbox.checked;
      }
    });
  });

  tbody.querySelectorAll("[data-web-action]").forEach(button => {
    button.addEventListener("click", () => {
      runWebValidationAction(button);
    });
  });
}

async function runWebValidationAction(button) {
  const actionId = button.dataset.webAction;
  const summary = document.getElementById("webValidationSummaryText");

  if (!actionId) return;

  const checkbox = document.querySelector(
    `[data-web-approval="${CSS.escape(actionId)}"]`
  );

  if (!checkbox?.checked) {
    if (summary) {
      summary.textContent = "Explicit approval is required.";
    }

    return;
  }

  const previousText = button.textContent;

  button.disabled = true;
  button.textContent = "Running";

  if (summary) {
    summary.textContent = "Running controlled web validation...";
  }

  try {
    const response = await fetch(
      getEndpoint(
        "webValidationRun",
        "/pentest/web-validation/run"
      ),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          action_id: actionId,
          approved: true
        })
      }
    );

    const data = await response.json();

    if (!response.ok || !data.ok) {
      if (summary) {
        summary.textContent =
          data.error || "Web-validation action was rejected.";
      }

      button.disabled = false;
      button.textContent = previousText;
      return;
    }

    appendWebValidationRun(data);
    updateWebValidationSummary(data.web_validation || {});

    button.textContent = "Done";
  } catch (error) {
    if (summary) {
      summary.textContent = "Controlled web validation failed.";
    }

    button.disabled = false;
    button.textContent = previousText;
  }
}

function appendWebValidationRun(run) {
  const tbody = document.getElementById("webValidationRunsBody");

  if (!tbody) return;

  const evidence = (run.evidence || []).join("; ");

  const row = `
    <tr>
      <td class="mono small">
        ${escapeHtml(run.timestamp || "-")}
      </td>

      <td>
        <span class="state ${webValidationStateClass(run.status)}">
          ${escapeHtml(run.status || "unknown")}
        </span>
      </td>

      <td class="mono">
        ${escapeHtml(run.target)}:${escapeHtml(run.port)}
      </td>

      <td class="mono small">
        ${escapeHtml(run.method)}
        ${escapeHtml(run.endpoint)}
        (${escapeHtml(run.parameter)})
      </td>

      <td class="small">
        ${escapeHtml(run.summary || "")}

        ${
          evidence
            ? `<br><span class="muted">${escapeHtml(evidence)}</span>`
            : ""
        }
      </td>
    </tr>
  `;

  if (tbody.querySelector("td[colspan]")) {
    tbody.innerHTML = row;
  } else {
    tbody.insertAdjacentHTML("beforeend", row);
  }
}

function updateWebValidationSummary(web) {
  const summary = document.getElementById("webValidationSummaryText");

  if (!summary) return;

  summary.textContent =
    `${web.confirmed || 0} confirmed, ` +
    `${web.not_confirmed || 0} not confirmed, ` +
    `${web.blocked || 0} blocked, ` +
    `${web.failed || 0} failed.`;
}