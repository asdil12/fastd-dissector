fastd_proto  = Proto("fastd", "F.A.S.T.D")

local fastd_types = {
	[1] = "Handshake Packet",
	[2] = "Payload Packet",
}

local handshake_types = {
	[1] = "request",
	[2] = "reply",
	[3] = "finish",
}

local reply_codes = {
	[0] = "success",
	[1] = "mandatory record missing",
	[2] = "unacceptable value",
}

local modi = {
	[0] = "TAP mode",
	[1] = "TUN mode",
}

local f = fastd_proto.fields

f.type = ProtoField.uint8("fastd.type", "Type", base.HEX, fastd_types)

f.handshake_type = ProtoField.uint8("fastd.handshake_type", "Handshake type", base.HEX, handshake_types)
f.reply_code = ProtoField.uint8("fastd.reply_code", "Reply Code", base.HEX, reply_codes)
f.mode = ProtoField.uint8("fastd.mode", "Mode", base.HEX, modi)
f.proto_name = ProtoField.string("fastd.proto_name", "Protocol name", FT_STRING)
f.version_name = ProtoField.string("fastd.version_name", "Version name", FT_STRING)
f.mtu = ProtoField.uint16("fastd.mtu", "MTU", base.DEC)
f.method_name = ProtoField.string("fastd.method_name", "Method name", FT_STRING)
f.method_list = ProtoField.string("fastd.method_list", "Method list", FT_STRING)
f.sender_key = ProtoField.bytes("fastd.sender_key", "Sender key", base.HEX)
f.recpt_key = ProtoField.bytes("fastd.recpt_key", "Recipient key", base.HEX)
f.sender_hskey = ProtoField.bytes("fastd.sender_hskey", "Sender Handshake key", base.HEX)
f.recpt_hskey = ProtoField.bytes("fastd.recpt_hskey", "Recipient Handshake key", base.HEX)

function fastd_proto.dissector(buffer, pinfo, tree)
	local subtree = tree:add(fastd_proto, buffer)
	subtree:add(f.type, buffer(0,1))
	if buffer(0,1):uint() == 1 then
		pinfo.cols.protocol = "FASTD"
		pinfo.cols.info = "Handshake"
		subtree:append_text(", Handshake")
		tlv_records_len = buffer(2,2):uint()
		offset = 4
		while (offset-4) < tlv_records_len do
			record_type = buffer(offset,2):le_uint()
			record_length = buffer(offset+2,2):le_uint()
			offset = offset + 4
			if record_type == 0x00 then
				subtree:add(f.handshake_type, buffer(offset,record_length))
				type_str = handshake_types[buffer(offset,record_length):uint()]
				pinfo.cols.info:append(" (Type: "..type_str..")")
				subtree:append_text(" ("..type_str..")")
			elseif record_type == 0x01 then
				subtree:add(f.reply_code, buffer(offset,record_length))
			elseif record_type == 0x04 then
				subtree:add(f.mode, buffer(offset,record_length))
			elseif record_type == 0x05 then
				subtree:add(f.proto_name, buffer(offset,record_length))
			elseif record_type == 0x06 then
				subtree:add(f.sender_key, buffer(offset,record_length))
			elseif record_type == 0x07 then
				subtree:add(f.recpt_key, buffer(offset,record_length))
			elseif record_type == 0x08 then
				subtree:add(f.sender_hskey, buffer(offset,record_length))
			elseif record_type == 0x09 then
				subtree:add(f.recpt_hskey, buffer(offset,record_length))
			elseif record_type == 0x0B then
				subtree:add_le(f.mtu, buffer(offset,record_length))
			elseif record_type == 0x0C then
				subtree:add(f.method_name, buffer(offset,record_length))
			elseif record_type == 0x0D then
				subtree:add(f.version_name, buffer(offset,record_length))
			elseif record_type == 0x0E then
				subtree:add(f.method_list, buffer(offset,record_length))
			else
				offset = tlv_records_len + 4
			end
			offset = offset + record_length
		end
	elseif buffer(0,1):uint() == 2 then
		subtree:append_text(", Payload")
		ethernet_dissector = Dissector.get("eth")

		-- skip over the header in front of the encapsulated ethernet frame
		sub_buf = buffer(1, buffer:len() - 1):tvb()
		ethernet_dissector:call(sub_buf, pinfo, tree)
	end
end

-- load the udp port table
udp_table = DissectorTable.get("udp.port")

-- register our protocol                                  
udp_table:add(10004, fastd_proto)
udp_table:add(10005, fastd_proto)
udp_table:add(10014, fastd_proto)
