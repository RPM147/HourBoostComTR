(function () {
  "use strict";

  var root = document.getElementById("reset-password-action");
  if (!root) return;

  var csrfMeta = document.querySelector('meta[name="csrf-token"]');
  var params = new URLSearchParams(window.location.hash.slice(1));
  var token = params.get("token") || "";
  var loading = document.getElementById("reset-loading");
  var form = document.getElementById("reset-form");
  var errorCard = document.getElementById("reset-error");
  var errorMessage = document.getElementById("reset-error-message");
  var message = document.getElementById("msg");
  var button = document.getElementById("btn");

  window.history.replaceState(
    null,
    document.title,
    window.location.pathname + window.location.search
  );

  function postJson(path, payload) {
    return fetch(path + window.location.search, {
      method: "POST",
      credentials: "same-origin",
      referrerPolicy: "no-referrer",
      headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "X-CSRFToken": csrfMeta.content
      },
      body: JSON.stringify(payload)
    }).then(function (response) {
      return response.json().then(function (body) {
        return { response: response, body: body };
      });
    });
  }

  function showError(text) {
    loading.hidden = true;
    form.hidden = true;
    errorMessage.textContent = text;
    errorCard.hidden = false;
    token = "";
  }

  if (!/^[A-Za-z0-9_-]{43}$/.test(token) || !csrfMeta) {
    showError(root.dataset.invalidMessage);
    return;
  }

  postJson(root.dataset.validateEndpoint, { token: token })
    .then(function (result) {
      if (!result.response.ok || !result.body.ok) {
        showError(result.body.error || root.dataset.invalidMessage);
        return;
      }
      loading.hidden = true;
      form.hidden = false;
    })
    .catch(function () {
      showError(root.dataset.requestError);
    });

  document.querySelectorAll("[data-password-target]").forEach(function (toggle) {
    toggle.addEventListener("click", function () {
      var input = document.getElementById(toggle.dataset.passwordTarget);
      var reveal = input.type === "password";
      input.type = reveal ? "text" : "password";
      toggle.textContent = reveal
        ? root.dataset.hidePassword
        : root.dataset.showPassword;
    });
  });

  button.addEventListener("click", function () {
    var first = document.getElementById("pass1").value;
    var second = document.getElementById("pass2").value;
    message.className = "msg";

    if (!first || !second) {
      message.textContent = root.dataset.missingFields;
      message.className = "msg er";
      return;
    }
    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{10,}$/.test(first)) {
      message.textContent = root.dataset.weakPassword;
      message.className = "msg er";
      return;
    }
    if (first !== second) {
      message.textContent = root.dataset.passwordMismatch;
      message.className = "msg er";
      return;
    }

    button.textContent = root.dataset.updatingLabel;
    button.disabled = true;
    postJson(root.dataset.submitEndpoint, {
      token: token,
      password: first
    })
      .then(function (result) {
        if (result.response.ok && result.body.ok) {
          token = "";
          message.textContent = result.body.message + " " + root.dataset.redirectMessage;
          message.className = "msg ok";
          window.setTimeout(function () {
            window.location.href = root.dataset.homePath;
          }, 2500);
          return;
        }
        message.textContent = result.body.error || root.dataset.requestError;
        message.className = "msg er";
        button.textContent = root.dataset.submitLabel;
        button.disabled = false;
      })
      .catch(function () {
        message.textContent = root.dataset.requestError;
        message.className = "msg er";
        button.textContent = root.dataset.submitLabel;
        button.disabled = false;
      });
  });
})();
