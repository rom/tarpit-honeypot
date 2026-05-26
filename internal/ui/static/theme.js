// theme.js — reads the tarpit_theme and tarpit_size cookies and applies the
// corresponding classes to <html> BEFORE the body parses, so themed / scaled
// deployments render correctly on the first paint. Loaded synchronously (no
// defer) from the head template.
//
// Both cookie values are constrained to [a-z][a-z0-9-]{0,31} on the way IN
// (the /theme and /size handlers validate against an allowlist) and again
// here on the way OUT — a tampered cookie cannot inject anything into the
// resulting class string.
(function () {
  try {
    var t = document.cookie.match(/(?:^|; )tarpit_theme=([a-z][a-z0-9-]{0,31})(?:;|$)/);
    if (t) document.documentElement.classList.add('theme-' + t[1]);
    var s = document.cookie.match(/(?:^|; )tarpit_size=([a-z][a-z0-9-]{0,15})(?:;|$)/);
    if (s) document.documentElement.classList.add('size-' + s[1]);
  } catch (e) {
    // Pre-paint script must never throw — fall back to default theme + size.
  }
})();
