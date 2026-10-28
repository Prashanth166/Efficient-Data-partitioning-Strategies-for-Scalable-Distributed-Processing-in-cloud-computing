document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".flash-close").forEach(button => {
    button.addEventListener("click", () => button.closest(".flash")?.remove());
  });
  const fileInput = document.querySelector("#file-input");
  const selectedFile = document.querySelector("#selected-file");
  if (fileInput && selectedFile) {
    fileInput.addEventListener("change", () => {
      selectedFile.textContent = fileInput.files.length ? fileInput.files[0].name : "No file selected";
    });
  }
  document.querySelectorAll("[data-confirm]").forEach(button => {
    button.addEventListener("click", event => {
      if (!window.confirm(button.dataset.confirm || "Continue?")) event.preventDefault();
    });
  });
});
