-- Fake Apache Struts 2 web app (handler: lua, HTTP). Struts2 is the canonical
-- OGNL-injection target: CVE-2017-5638 (S2-045 — OGNL in the Content-Type
-- header) and CVE-2023-50164 (path-traversal file upload). Serves a believable
-- Struts showcase page and flags OGNL payloads in the Content-Type / body /
-- *.action paths.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
path = path or "/"

local clen, ctype = 0, ""
for _ = 1, 50 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  local hl = string.lower(h)
  if hl:find("^content%-length:") then clen = tonumber((h:match(":%s*(%d+)"))) or 0 end
  if hl:find("^content%-type:") then
    ctype = h
    -- S2-045: OGNL expression smuggled in the Content-Type header.
    if h:find("%%{") or h:find("#context") or h:find("multipart/form%-data.*[%%#]") then
      flag("struts-cve-2017-5638-probe")
      meta("ognl_content_type", (h:gsub("[\r\n]", "")))
    end
  end
end
if clen > 0 then
  if clen > 8192 then clen = 8192 end
  local body = conn:read(clen) or ""
  meta("post_body", body)
  if body:find("%%{") or body:find("ognl") or body:find("getRuntime") then
    flag("struts-ognl-injection")
  end
end

local p = string.lower(path)
flag("struts-access")
if p:find("%.action") or p:find("%.do") then flag("struts-action-probe") end

local html = "<html><head><title>Struts2 Showcase</title></head><body>" ..
  "<h1>Struts 2 Showcase</h1></body></html>"
conn:write("HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html\r\n")
conn:write("Connection: close\r\nContent-Length: " .. tostring(#html) .. "\r\n\r\n" .. html)
