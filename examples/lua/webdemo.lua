-- Load with TSHARK_LUA_SCRIPTS='["/absolute/path/to/webdemo.lua"]'.
-- Example: UDP/19000, one-byte message type followed by a UTF-8 payload.
local protocol = Proto("webdemo", "WebTshark Lua Demo")
local kind = ProtoField.uint8("webdemo.kind", "Message type", base.DEC)
local body = ProtoField.string("webdemo.body", "Message body")
protocol.fields = {kind, body}
function protocol.dissector(buffer, pinfo, tree)
  if buffer:len() < 1 then return end
  pinfo.cols.protocol = "WEBDEMO"
  local subtree = tree:add(protocol, buffer())
  subtree:add(kind, buffer(0, 1))
  if buffer:len() > 1 then subtree:add(body, buffer(1)) end
  pinfo.cols.info = "Lua message type " .. buffer(0, 1):uint()
end
DissectorTable.get("udp.port"):add(19000, protocol)
