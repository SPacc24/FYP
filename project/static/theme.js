(function () {
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

  const savedTheme =
    localStorage.getItem(STORAGE_KEY) || "dark";

  applyTheme(savedTheme);

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