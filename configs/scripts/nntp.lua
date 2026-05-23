-- Fake NNTP news server (handler: lua, TCP 119). Greets, advertises a
-- per-host server id, and walks the common reader commands (GROUP / LIST /
-- ARTICLE / AUTHINFO / POST). Captures credentials and any POST attempt.
-- Nothing is stored or served.

local p = personality()
conn:write("200 " .. p.hostname .. " InterNetNews NNRP server ready (posting ok)\r\n")

for _ = 1, 24 do
  local line = conn:readline()
  if not line then break end
  local c = (line:gsub("[\r\n]", ""))
  local verb = string.upper(c:match("^(%S+)") or "")
  if verb == "QUIT" then
    conn:write("205 closing connection\r\n")
    break
  elseif verb == "AUTHINFO" then
    meta("authinfo", c)
    flag("nntp-auth-attempt")
    conn:write("281 Authentication accepted\r\n")
  elseif verb == "LIST" then
    conn:write("215 list of newsgroups follows\r\n")
    conn:write("alt.test 0000000001 0000000000 y\r\ncomp.lang.lua 12 1 y\r\n.\r\n")
  elseif verb == "GROUP" then
    meta("group", c)
    conn:write("211 12 1 12 " .. (c:match("%s+(%S+)") or "alt.test") .. "\r\n")
  elseif verb == "POST" then
    flag("nntp-post-attempt")
    conn:write("440 posting not allowed\r\n")
  elseif verb == "ARTICLE" or verb == "HEAD" or verb == "BODY" then
    conn:write("430 no such article\r\n")
  elseif verb == "MODE" then
    conn:write("200 reader mode, posting permitted\r\n")
  elseif #verb > 0 then
    conn:write("500 command not recognized\r\n")
  end
end
