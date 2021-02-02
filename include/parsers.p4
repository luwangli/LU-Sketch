parser MyParser (packet_in packet,
		out headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {
	
	state start {
		transition select(standard_metadata.ingress_port) {
		1 : parse_ethernet;// for simpleness, only parse packet from port 1
		2 : parse_ethernet;
		}
		//parse_ethernet;
	}

	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			TYPE_IPV4	: parse_ipv4;
		}
	}

	state parse_ipv4 {
		packet.extract(hdr.ipv4);
		transition accept;
	}
/*
	state parse_ipv4 {
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
			PROTO_TCP	: parse_tcp;
			PROTO_UDP	: parse_udp;
		}
	}

	state parse_tcp {
		packet.extract(hdr.tcp);
		transition accept;
	}

	state parse_udp {
		packet.extract(hdr.udp);
		transition accept;
	}
*/
}

