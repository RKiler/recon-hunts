const toggle = document.getElementById("passwordToggle");
const password = document.getElementById("password");

if (toggle && password) {
  toggle.addEventListener("click", () => {
    const showing = password.type === "text";
    password.type = showing ? "password" : "text";
    toggle.textContent = showing ? "Show" : "Hide";
    toggle.setAttribute("aria-pressed", String(!showing));
    password.focus();
  });
}
