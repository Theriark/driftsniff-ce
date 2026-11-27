// The picture form of the Account page (templates/account.html). The picture is sent as the
// request body with the session's CSRF value in the X-CSRF-Token header: the browser-write check
// reads a form body only up to 16 KB, so a form post could not carry it. The form is hidden in
// the page and shown here, so a browser without script never offers what it cannot send.
document.querySelectorAll("[data-account-picture]").forEach((form) => {
  const input = form.querySelector('input[type="file"]');
  const error = form.querySelector("[data-account-picture-error]");
  const button = form.querySelector('button[type="submit"]');
  const max = Number(form.getAttribute("data-max-bytes"));
  const say = (text) => {
    error.textContent = text;
    error.hidden = !text;
    input.setAttribute("aria-invalid", text ? "true" : "false");
    if (text) {
      // a refusal ends the earlier success: drop its banner and its ?done=
      document.querySelectorAll(".settings-banners").forEach((banner) => banner.remove());
      if (window.location.search.includes("done=")) {
        window.history.replaceState(null, "", window.location.pathname);
      }
    }
  };
  form.hidden = false;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const file = input.files && input.files[0];
    if (!file) {
      say("Choose a picture first.");
      return;
    }
    if (file.size > max) {
      say(`The picture must be at most ${Math.round(max / 1024)} KB.`);
      return;
    }
    say("");
    button.disabled = true;
    try {
      const response = await fetch(form.action, {
        method: "POST",
        headers: {
          "X-CSRF-Token": form.querySelector('input[name="csrf_token"]').value,
          "Content-Type": file.type || "application/octet-stream",
        },
        body: file,
        credentials: "same-origin",
      });
      const answer = await response.json().catch(() => ({}));
      if (response.ok && typeof answer.location === "string" && answer.location.startsWith("/account")) {
        window.location.assign(answer.location);
        return;
      }
      say(answer.detail || "The picture was not saved. Try again.");
    } catch (failure) {
      say("The picture was not saved: the connection failed. Try again.");
    }
    button.disabled = false;
  });
});
