// theme.js — reads the per-instance tarpit_theme_<port> / tarpit_size_<port>
// cookies and applies the corresponding classes to <html> BEFORE the body
// parses, so themed / scaled deployments render correctly on the first paint.
// Loaded synchronously (no defer) from the head template.
//
// The <port> suffix is location.port (matching the server, which derives it
// from the request Host). Cookies are scoped by host only — the browser ignores
// the port — so without the suffix two sensor instances on the same host
// (127.0.0.1:8088 and :8089) would share one theme/size cookie and override each
// other. The suffix keeps each instance's preference separate even though every
// sibling's cookie is still delivered to all of them.
//
// Both cookie values are constrained to [a-z][a-z0-9-]{0,31} on the way IN (the
// /theme and /size handlers validate against an allowlist) and again here on the
// way OUT — a tampered cookie cannot inject anything into the class string.
(function () {
  try {
    var p = location.port || "0"; // digits only; matches the server's instancePort
    function pick(name, max) {
      var m = document.cookie.match(
        new RegExp("(?:^|; )" + name + "=([a-z][a-z0-9-]{0," + max + "})(?:;|$)"));
      return m ? m[1] : null;
    }
    var t = pick("tarpit_theme_" + p, 31);
    if (t) document.documentElement.classList.add('theme-' + t);
    var s = pick("tarpit_size_" + p, 15);
    if (s) document.documentElement.classList.add('size-' + s);
  } catch (e) {
    // Pre-paint script must never throw — fall back to default theme + size.
  }
})();
