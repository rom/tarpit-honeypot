-- Fake SMTP (handler: lua). The 220 greeting carries a live RFC822-style
-- date and a per-host hostname; EHLO advertises capabilities; HELO / MAIL /
-- RCPT / AUTH are captured. Nothing is relayed or executed.
--
-- Demonstrates: time.utc (live timestamp in the banner), personality
-- (stable per-source hostname), meta/flag (capture + detection).

local p = personality()
local host_name = p.hostname .. ".corp.internal"
conn:write("220 " .. host_name .. " ESMTP Postfix; " .. time.utc() .. "\r\n")

for _ = 1, 24 do
  local line = conn:readline()
  if not line then break end
  local c = (line:gsub("[\r\n]", ""))
  local verb = string.upper(c:sub(1, 4))
  if verb == "EHLO" or verb == "HELO" then
    meta("helo", c)
    conn:write("250-" .. host_name .. "\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")
  elseif verb == "AUTH" then
    flag("smtp-auth-attempt")
    meta("auth", c)
    sleep(150 + rng:int(300))
    conn:write("535 5.7.8 Error: authentication failed\r\n")
  elseif verb == "MAIL" then
    meta("mail_from", c)
    conn:write("250 2.1.0 Ok\r\n")
  elseif verb == "RCPT" then
    meta("rcpt_to", c)
    conn:write("250 2.1.5 Ok\r\n")
  elseif verb == "DATA" then
    conn:write("354 End data with <CR><LF>.<CR><LF>\r\n")
  elseif verb == "QUIT" then
    conn:write("221 2.0.0 Bye\r\n")
    break
  elseif #c > 0 then
    conn:write("250 2.0.0 Ok\r\n")
  end
end
