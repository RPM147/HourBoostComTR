(function () {
  "use strict";

  var root = document.getElementById("token-action");
  if (!root) return;

  var button = document.getElementById("token-action-button");
  var icon = document.getElementById("token-action-icon");
  var title = document.getElementById("token-action-title");
  var message = document.getElementById("token-action-message");
  var returnLink = document.getElementById("token-action-return");
  var csrfMeta = document.querySelector('meta[name="csrf-token"]');
  var params = new URLSearchParams(window.location.hash.slice(1));
  var token = params.get("token") || "";

  window.history.replaceState(
    null,
    document.title,
    window.location.pathname + window.location.search
  );

  function finish(ok, text) {
    icon.textContent = ok ? "✅" : "❌";
    title.textContent = ok ? root.dataset.successTitle : root.dataset.errorTitle;
    title.className = "title " + (ok ? "success" : "error");
    message.textContent = text;
    button.hidden = true;
    returnLink.hidden = false;
    returnLink.classList.toggle("error-btn", !ok);
    token = "";
  }

  if (!/^[A-Za-z0-9_-]{43}$/.test(token) || !csrfMeta) {
    finish(false, root.dataset.invalidMessage);
    return;
  }

  button.addEventListener("click", function () {
    button.disabled = true;
    fetch(root.dataset.endpoint + window.location.search, {
      method: "POST",
      credentials: "same-origin",
      referrerPolicy: "no-referrer",
      headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "X-CSRFToken": csrfMeta.content
      },
      body: JSON.stringify({ token: token })
    })
      .then(function (response) {
        return response.json().then(function (payload) {
          return { response: response, payload: payload };
        });
      })
      .then(function (result) {
        if (result.response.ok && result.payload.ok) {
          finish(true, result.payload.message);
          return;
        }
        finish(
          false,
          result.payload.error || root.dataset.invalidMessage
        );
      })
      .catch(function () {
        message.textContent = root.dataset.requestError;
        message.className = "message error";
        button.disabled = false;
      });
  });
})();
