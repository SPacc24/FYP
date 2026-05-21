function applyModeBehavior() {
  const modeElement = document.getElementById("activeModeValue");
  const selectedMode = modeElement ? modeElement.dataset.mode : "hybrid";

  const hasAiPlanElement = document.getElementById("hasAiPlanValue");
  const hasAiPlan = hasAiPlanElement
    ? hasAiPlanElement.dataset.hasAiPlan === "true"
    : false;

  const checkboxes = document.querySelectorAll(
    'input[name="selected_techniques"]'
  );

  if (!checkboxes.length) return;

  if (selectedMode === "auto") {
    checkboxes.forEach(cb => {
      const isAiSelected = cb.dataset.aiSelected === "true";
      cb.checked = hasAiPlan ? isAiSelected : true;
      cb.disabled = false;

      cb.addEventListener("click", function (event) {
        event.preventDefault();
      });
    });
  }

  else if (selectedMode === "hybrid") {
    checkboxes.forEach(cb => {
      const isAiSelected = cb.dataset.aiSelected === "true";
      cb.checked = hasAiPlan ? isAiSelected : true;
      cb.disabled = false;
    });
  }

  else if (selectedMode === "manual") {
    checkboxes.forEach(cb => {
      cb.checked = false;
      cb.disabled = false;
    });
  }
}

function getSelectedTechniqueIds() {
  return Array.from(
    document.querySelectorAll('input[name="selected_techniques"]:checked')
  ).map(el => el.value);
}