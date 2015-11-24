fastd_proto  = Proto("fastd", "Fast and Secure Tunneling Daemon")

local fastd_types = {
	[1] = "fastd Handshake Packet",
	[2] = "fastd Payload Packet",
}

local f = fastd_proto.fields

f.type = ProtoField.uint8("fastd.type", "Type", base.HEX, fastd_types)

function fastd_proto.dissector(buffer, pinfo, tree)
   local subtree = tree:add(fastd_proto, buffer, "FASTD")
   subtree:add(f.type, buffer(0,1))

   ethernet_dissector = Dissector.get("eth")

   -- skip over the header in front of the encapsulated ethernet frame
   sub_buf = buffer(1, buffer:len() - 1):tvb()
   ethernet_dissector:call(sub_buf, pinfo, tree)
end

-- load the udp port table
udp_table = DissectorTable.get("udp.port")

-- register our protocol                                  
udp_table:add(10004, fastd_proto)
udp_table:add(10005, fastd_proto)
