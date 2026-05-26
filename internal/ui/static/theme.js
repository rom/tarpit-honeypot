// theme.js — reads the `tarpit_theme` cookie and applies a theme class to
// <html> BEFORE the body parses, so themed deployments render correctly on
// the first paint. Loaded synchronously (no defer) from the head template.
//
// The cookie value is constrained to [a-z][a-z0-9-]{0,31} both by the server-
// side /theme handler that sets it and by the regex below — so even a tampered
// cookie cannot inject anything into the resulting class string.
(function () {
  try {
    var m = document.cookie.match(/(?:^|; )tarpit_theme=([a-z][a-z0-9-]{0,31})(?:;|$)/);
    if (m) {
      document.documentElement.classList.add('theme-' + m[1]);
    }
  } catch (e) {
    // Pre-paint script must never throw — fall back to the default theme.
  }
})();
