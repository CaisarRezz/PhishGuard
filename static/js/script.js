document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector(".scan-form");
  const button = document.getElementById("scan-button");
  if (form && button) {
    form.addEventListener("submit", () => {
      button.disabled = true;
      button.textContent = "Analyzing...";
    });
  }
});
