-- Fake MinIO / S3 object storage (handler: lua, HTTP 9000). An open S3
-- endpoint leaks buckets. Answers ListBuckets with an S3-style XML/error and
-- captures the bucket/object path + AWS signature.
local reqline = conn:readline() or ""
local method, path = reqline:match("^(%u+)%s+(%S+)")
meta("request_line", (reqline:gsub("[\r\n]", "")))
for _ = 1, 40 do
  local h = conn:readline(); if not h or h == "\r\n" or h == "\n" then break end
  if string.lower(h):find("^authorization:") then meta("aws_auth",(h:gsub("[\r\n]",""))); flag("http-auth-attempt") end
end
local function send(code, body)
  conn:write("HTTP/1.1 " .. code .. "\r\nServer: MinIO\r\nContent-Type: application/xml\r\n")
  conn:write("Content-Length: " .. tostring(#body) .. "\r\nConnection: close\r\n\r\n" .. body)
end
flag("minio-access")
path = path or "/"
if path == "/" or path == "" then
  send("200 OK", '<?xml version="1.0"?><ListAllMyBucketsResult><Buckets></Buckets></ListAllMyBucketsResult>')
elseif path:find("^/minio/health") then
  send("200 OK", "")
else
  meta("s3_path", path)
  flag("minio-bucket-access")
  send("403 Forbidden", '<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>')
end
