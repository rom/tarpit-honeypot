-- Fake Apache CouchDB (handler: lua, HTTP 5984). An exposed CouchDB admin
-- API is a classic data-exfil / "admin party" target. Answers the welcome
-- doc and _all_dbs, captures the request + any Authorization header, and
-- flags database enumeration. No data is served.

local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline()
  if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then
    meta("authorization", (h:gsub("[\r\n]", "")))
    flag("http-auth-attempt")
  end
end

local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: CouchDB/3.3.3 (Erlang OTP/25)\r\n")
  conn:write("Content-Type: application/json\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end

path = path or "/"
if path == "/" then
  send("200 OK", '{"couchdb":"Welcome","version":"3.3.3","uuid":"' .. rng:hex(16) ..
    '","vendor":{"name":"The Apache Software Foundation"}}')
elseif path:find("^/_all_dbs") then
  flag("couchdb-db-enumeration")
  send("200 OK", '["_replicator","_users","prod","sessions","payments"]')
elseif path:find("^/_utils") then
  flag("couchdb-fauxton-access")
  send("200 OK", '{"fauxton":"ok"}')
else
  flag("couchdb-unauth-access")
  send("404 Object Not Found", '{"error":"not_found","reason":"missing"}')
end
