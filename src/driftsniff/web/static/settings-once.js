/* The answers of the settings page that must not run again on a reload (THE-1278).

   Making an API token, showing the webhook signing key and sending a test message are posts
   answered with the settings page itself: the token or the key in a card shown once, or the
   result of the test. A reload of such an answer would post the form again and make another
   token, show (and audit) the key again or send another test. The settings page loads this file
   only on those answers. It replaces the history entry with GET /settings, so a reload, or a
   return to the page through the history, asks for the plain page and the value stays shown
   once. Without script the browser still asks before it posts a form again. */
(function () {
  "use strict";

  if (window.history && typeof window.history.replaceState === "function") {
    window.history.replaceState(null, "", "/settings");
  }
})();
