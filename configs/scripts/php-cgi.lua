-- Fake PHP-CGI server (handler: lua, HTTP). PHP running as CGI is exploited via
-- CVE-2024-4577 (argument injection — a soft-hyphen % AD before -d lets an
-- attacker pass php.ini directives like allow_url_include in the query string)
-- and the classic CVE-2012-1823. Serves a believable PHP page + flags the
-- argument-injection query strings.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"

local clen = 0
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
end
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  local body = conn:read(clen) or ""
  meta("post_body", body)
  if body:find("allow_url_include") or body:find("auto_prepend_file") then flag("php-cgi-rce-probe") end
end

local ver = rng:choice({ "8.1.27", "8.2.12", "7.4.33", "8.3.2" })
meta("php_version", ver)
local p = string.lower(path)
flag("php-cgi-access")
-- CVE-2024-4577: a "-" (often %ad soft-hyphen) followed by -d / cgi.force_redirect.
if p:find("%%ad") or p:find("php%-cgi") or p:find("cgi%.force") or p:find("allow_url_include") then
  flag("php-cve-2024-4577-probe")
end
if p:find("php://input") or p:find("auto_prepend") then flag("php-cve-2012-1823-probe") end

local html = "<html><head><title>PHP</title></head><body>PHP/" .. ver .. "</body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Win32)\r\nX-Powered-By: PHP/" .. ver .. "\r\n")
conn:write("Content-Type: text/html\r\nConnection: close\r\nContent-Length: " ..
  tostring(#html) .. "\r\n\r\n" .. html)
