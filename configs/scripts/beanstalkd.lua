-- Fake beanstalkd work queue (handler: lua, TCP 11300). beanstalkd has no
-- auth at all, so an exposed one leaks jobs and accepts writes. Answers
-- stats / list-tubes and captures put / use / reserve. Nothing is queued.

for _ = 1, 16 do
  local line = conn:readline()
  if not line then break end
  local c = (line:gsub("[\r\n]", ""))
  local verb = string.lower(c:match("^(%S+)") or "")
  if verb == "stats" then
    local body = table.concat({
      "current-jobs-ready: " .. tostring(rng:int(40)),
      "current-jobs-reserved: 0",
      "cmd-put: " .. tostring(rng:int(9000)),
      "current-connections: " .. tostring(1 + rng:int(8)),
      "uptime: " .. tostring(time.uptime()),
      "version: 1.13",
    }, "\n") .. "\n"
    conn:write("OK " .. tostring(#body) .. "\r\n" .. body .. "\r\n")
  elseif verb == "list-tubes" then
    local body = "---\n- default\n- email\n- payments\n"
    conn:write("OK " .. tostring(#body) .. "\r\n" .. body .. "\r\n")
  elseif verb == "put" then
    meta("beanstalk_put", c)
    flag("beanstalkd-write-attempt")
    conn:write("INSERTED " .. tostring(1 + rng:int(9999)) .. "\r\n")
  elseif verb == "use" or verb == "watch" then
    conn:write("USING " .. (c:match("%s+(%S+)") or "default") .. "\r\n")
  elseif verb == "reserve" or verb == "reserve-with-timeout" then
    conn:write("TIMED_OUT\r\n")
  elseif verb == "quit" then
    break
  elseif #verb > 0 then
    conn:write("UNKNOWN_COMMAND\r\n")
  end
end
