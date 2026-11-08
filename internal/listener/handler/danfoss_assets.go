package handler

import "encoding/base64"

// Web assets modelled on a live, internet-facing Danfoss AK-SM "StoreView Web"
// refrigeration system manager. The favicon, logo and response headers below are
// captured verbatim from the real device; the landing page is a self-contained
// static login styled to match it.
//
// Why not the device's real index.html? StoreView is an Angular single-page app:
// its real landing document is an empty <app-root> plus hashed JS/CSS bundles
// that code-split into further lazy chunks and an i18n fetch, and only render
// once the live xml.cgi backend answers. Served by a honeypot — which has none
// of that — the genuine shell renders a blank page ("Loading chunk failed").
// So we keep the exact fingerprint head (title, favicon/logo refs) and the exact
// nginx header set, but give the body a real, deterministic login form (posting
// to xml.cgi?action=getauth, which the handler recognizes and captures). Nothing
// here is executed — it is static response data.

// danfossIndexHTML is the landing page served at "/": a self-contained StoreView
// login (no external bundles, so it always renders), using the device's real
// logo and the StoreView admin theme's look (Roboto, #188ae2 primary accent).
const danfossIndexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Danfoss StoreView</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/x-icon" href="favicon.ico">
  <link rel="shortcut icon" sizes="196x196" href="assets/images/logo.png">
  <style>
    html,body{height:100%;margin:0}
    body{font-family:Roboto,"Segoe UI",GeezaPro,"DejaVu Serif",sans-serif;background:#f5f5f5;
      color:#3b3e47;display:flex;align-items:center;justify-content:center}
    .card{background:#fff;width:360px;max-width:92vw;border-radius:3px;padding:30px 28px 24px;
      box-shadow:0 1px 3px rgba(0,0,0,.12),0 1px 2px rgba(0,0,0,.24);text-align:center}
    .brand img{width:64px;height:64px}
    h1{font-size:20px;font-weight:400;margin:10px 0 2px}
    .sub{font-size:12px;color:#98a6ad;margin-bottom:22px}
    form{text-align:left}
    label{display:block;font-size:12px;color:#98a6ad;margin:0 0 4px}
    input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:9px 10px;
      margin-bottom:16px;border:1px solid #e0e0e0;border-radius:2px;font-size:14px;color:#3b3e47}
    input:focus{outline:none;border-color:#188ae2}
    button{width:100%;padding:10px;background:#188ae2;color:#fff;border:0;border-radius:2px;
      font-size:14px;cursor:pointer;letter-spacing:.3px}
    button:hover{background:#1278c9}
    .foot{margin-top:20px;font-size:11px;color:#bdbdbd}
  </style>
</head>
<body class="simple-page menubar-light theme-primary">
  <div class="card">
    <div class="brand"><img src="assets/images/logo.png" alt="Danfoss"></div>
    <h1>StoreView</h1>
    <div class="sub">AK-SM 800A System Manager</div>
    <form action="xml.cgi?action=getauth" method="post">
      <label for="u">User name</label>
      <input id="u" type="text" name="username" autocomplete="username" autofocus>
      <label for="p">Password</label>
      <input id="p" type="password" name="password" autocomplete="current-password">
      <button type="submit">Log on</button>
    </form>
    <div class="foot">Danfoss &copy; StoreView Web</div>
  </div>
</body>
</html>
`

// danfossRespHeaders is the extra header block the live device emits on every
// response (an nginx config applied globally): the Server banner, the StoreView
// CORS policy — note the device-specific "aksm-auth" request header — and the
// no-store caching directive. svcHTTPResp adds Content-Type/Content-Length.
const danfossRespHeaders = "Server: nginx\r\n" +
	"Access-Control-Allow-Origin: *\r\n" +
	"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n" +
	"Access-Control-Allow-Headers: aksm-auth,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type\r\n" +
	"Cache-Control: no-store, no-cache\r\n"

// Base64 of the device's real favicon.ico (16x16 image/x-icon) and
// assets/images/logo.png (64x64 image/png). Decoded once at package load.
const danfossFaviconB64 = "AAABAAEAEBAAAAAAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAXGLUhFxi23xcXuP8XF7n/Fxa6/xcWu/8XFrz/FxW+/xcVvv8XFb3/Fxa8/xcWu/8XF7r/Fxe4/xcYtt8XGLUhFxi2nxcXuP8XFrv/FxW9/xcVv/9CQMz/FhPB/xYSxf8WEsb/FhLF/xYTw/8WE8L/FxS//xcWvf8XF7n/Fxi2rxcYt/8XF7r/FxW9/xcUwP8WE8P/4uH4/0I+0P+opev/UEvY/1BL2P9tat3/X1zY/xYSxP8XFMD/Fxa8/xcYt/8XGLf/Fxa7/xcUv/8WE8P/i4ji/5mX5//w8Pz/UErb/zIr1//T0vb/4uH5/yQe0P8WEMn/FhLE/xcVv/8XF7j/Fxe5/xcVvv8WE8L/FhLG/1BM1/+Kh+f/4uH5/yQb1v8VC9X/09H3//Dw/P/Fw/P/QTzW/xYRyP8WE8L/Fxe5/xcXuf8XFMH/FhHH/6il6/9BO9j/FQ3S/21n5P+YlO3/T0fh/8TB9v8UCtf/FQvV/zIr1/8WD8v/FhLE/xcXuv8XGLn/FxTB/4uI5P+npez/09H3/09I4P8xKN3/4uD6/9PR+P8xJuH/FAjb/zIo3f/T0ff/JB3S/xYQyP8XFrv/Fxe5/xcUwP+LiOP/trTv/+Lg+v+2svP/xMH2//Dw/f/w8P3/xMH3/8TB9v/i4Pr/trPy/21n4v8WEMr/FxW+/xcYuP8XFMD/FhHH/8XD8v9BOdv/FArY/yMY3v/i4Pv/09D5/yMW4v9ANeX/trL1/7ay8/+Khen/FQ/M/xcVvv8XGLj/FxW+/xYSxv8zLdL/FQzS/xUK1v+no/H/bGTq/2xk6/+Kg/D/FAbf/zEm4v+2svT/FQvW/xUOzv8XFL//Fxi3/xcWvP8WE8P/Qj3S/8XD8//i4fn/4uD6/xQI3P8UB97/8PD9/4qD7/9sZOr/FAnb/xUL1P8VD8z/Fxa8/xcYt/8XFrz/FxTA/xYSxP8kH87/8PD8/9PS9v8yKdz/T0bj//Dw/f+2svP/e3bo/xUL1P8VD83/FhLF/xcXuv8XGLf/Fxe6/xcVvv8WE8L/Qj7Q/4qI5P9QS9n/bWji/6ek7v9BOdz/09H3/yQc1P8WD8z/FhLF/xcUwP8XGLj/Fxi2nxcXuf8XFrv/FxW+/xYUwf8WE8P/FhLF/xYRyP8WD8v/Fg/L/zMu0P8WEcf/FhPC/xcUv/8XFrr/Fxi2nxcYtSEXGLbfFxe4/xcXuv8XFrz/Fxa8/xcWvf8XFb//FxW+/xcUwP8XFMH/FxW9/xcWu/8XF7n/Fxi23xgZtiH///8B////ARcYtmEXGLaBFxi3gRcYt4EXGLeBFxi4gRcYt4EXGLeBFxi4gRgZt4EYGbaBGBm2Yf///wH///8BAAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//w=="

const danfossLogoB64 = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAIAAAAlC+aJAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyJpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuMy1jMDExIDY2LjE0NTY2MSwgMjAxMi8wMi8wNi0xNDo1NjoyNyAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6MDM1NEExRERDNjQyMTFFOEFGODFCNzVDRTI2MUE3MkMiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6MDM1NEExRENDNjQyMTFFOEFGODFCNzVDRTI2MUE3MkMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENTNiAoV2luZG93cykiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDpFMDAwODhFQUM1NzYxMUU4QUVFRkEwOTA2OTU0RjA4QiIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDpFMDAwODhFQkM1NzYxMUU4QUVFRkEwOTA2OTU0RjA4QiIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/PqjqY6cAABZzSURBVHja1FoJmBTV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"

// danfossFavicon and danfossLogo hold the decoded asset bytes (served verbatim).
var (
	danfossFavicon = mustB64(danfossFaviconB64)
	danfossLogo    = mustB64(danfossLogoB64)
)

// mustB64 decodes an embedded, developer-supplied base64 asset at package load.
// The inputs are compile-time constants, so a decode error is a build-time bug.
func mustB64(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic("danfoss asset: " + err.Error())
	}
	return string(b)
}
