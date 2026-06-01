-- Fake Apache RocketMQ nameserver/broker (handler: lua, TCP 9876/10911).
-- RocketMQ exposes a length-prefixed JSON remoting protocol; CVE-2023-33246
-- lets an attacker push a malicious broker config to gain RCE via the
-- "updateBrokerConfig" admin command. We capture the request code / config
-- payload and flag the update-config primitive. Nothing is executed.
local ver = rng:choice({ "4.9.4", "4.9.7", "5.1.4", "5.3.0" })

for _ = 1, 8 do
  -- RocketMQ frames are [4-byte big-endian length][header+body]; but scanners
  -- and the CVE PoC also send readable JSON. Read what arrives and scan it.
  local chunk = conn:read(4096)
  if not chunk or #chunk == 0 then break end
  meta("rocketmq_bytes", tostring(#chunk))
  local low = string.lower(chunk)
  if low:find("updatebrokerconfig") or low:find("rocketmqhome") or low:find("filtersrvnums") then
    flag("rocketmq-config-push") -- CVE-2023-33246 broker-config RCE primitive
    meta("rocketmq_payload", chunk:sub(1, 512))
  elseif low:find("brokername") or low:find("clusterinfo") or low:find('"code"') then
    flag("rocketmq-admin-probe")
  else
    flag("rocketmq-probe")
  end
  -- A terse believable error keeps a scanner engaged without amplifying.
  conn:write('{"code":1,"language":"JAVA","version":' .. tostring(rng:int(400)) ..
    ',"remark":"broker[' .. personality().hostname .. '] not register, rocketmq ' .. ver .. '"}')
  break
end
