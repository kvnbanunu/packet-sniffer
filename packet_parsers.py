from printers import *

# Parse Ethernet header
def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    # Route payload based on EtherType
    match ether_type:
        case "0806":    #arp
            parse_arp_header(payload)
        case "0800":    #ipv4
            parse_ipv4_header(payload)
        case "86dd":    #ipv6
            parse_ipv6_header(payload)
        case _:
            print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
            print("  No parser available for this EtherType.")

    return ether_type, payload

# Parse ARP header
def parse_arp_header(hex_data):
    hardware_type = hex_data[:4]
    protocol_type = hex_data[4:8]
    hardware_size = hex_data[8:10]
    protocol_size = hex_data[10:12]
    operation = hex_data[12:16]
    sender_mac = hex_data[16:28]
    sender_ip = hex_data[28:36]
    target_mac = hex_data[36:48]
    target_ip = hex_data[48:56]

    print(f"ARP Header:")
    print_as_int(hardware_type, "Hardware Type:")
    print_as_int(protocol_type, "Protocol Type:")
    print_as_int(hardware_size, "Hardware Size:")
    print_as_int(protocol_size, "Protocol Size:")
    print_as_int(operation, "Operation:")
    print_mac_addr(sender_mac, "Sender MAC:")
    print_ipv4_addr(sender_ip, "Sender IP:")
    print_mac_addr(target_mac, "Target MAC:")
    print_ipv4_addr(target_ip, "Target IP:")

# Parse IPv4 header
def parse_ipv4_header(hex_data):
    version = hex_data[0]
    header_len = hex_data[1]
    diff_services = hex_data[2:4] # call print_diff_services
    total_len = hex_data[4:8]
    identification = hex_data[8:12]
    flags = hex_data[12:16] # call print_ipv4_flags
    ttl = hex_data[16:18]
    protocol = hex_data[18:20]
    checksum = hex_data[20:24]
    source_ip = hex_data[24:32]
    dest_ip = hex_data[32:40]

    print(f"IPv4 Header:")
    print_as_int(version, "Version:")
    print(f"  {'Header Length:':<25} {header_len:<20} | {int(header_len,16) * 4} bytes")
    print_diff_services(diff_services)
    print_as_int(total_len, "Total Length:")
    print_as_int(identification, "Identification:")
    print_ipv4_flags(flags)
    print(f"  {'Time to Live:':<25} {ttl:<20} | {int(ttl, 16)} hops")
    print_as_int(protocol, "Protocol:")
    print_as_int(checksum, "Checksum:")
    print_ipv4_addr(source_ip, "Source IP:")
    print_ipv4_addr(dest_ip, "Destination IP:")

    match int(protocol, 16):
        case 1: #icmp
            parse_icmp_header(hex_data[40:])
        case 6: #tcp
            parse_tcp_header(hex_data[40:])
        case 17: #udp
            parse_udp_header(hex_data[40:])
        case _:
            print(f"  {'Unsupported Protocol:':<25} {protocol}")

def parse_ipv6_header(hex_data):
    version = hex_data[0]
    traffic = hex_data[1:3]
    flow_label = hex_data[3:8]
    payload_len = hex_data[8:12]
    next_header = hex_data[12:14]
    hop_limit = hex_data[14:16]
    source_ip = hex_data[16:48]
    dest_ip = hex_data[48:80]
    payload = hex_data[80:]

    print("IPv6 Header:")
    print_as_int(version, "Version:")
    print_as_int(traffic, "Traffic Class:")
    print_as_int(flow_label, "Flow Label:")
    print_as_int(payload_len, "Payload Length:")
    print_as_int(next_header, "Next Header:")
    print_as_int(hop_limit, "Hop Limit:")
    print_ipv6_addr(source_ip, "Source Address:")
    print_ipv6_addr(dest_ip, "Destination Address:")

    match int(next_header, 16):
        case 0:
            parse_ipv6_hop(payload)
        case 6:
            parse_tcp_header(payload)
        case 17:
            parse_udp_header(payload)
        case 43:
            parse_ipv6_routing(payload)
        case 58:
            parse_icmpv6_header(payload)
        case _:
            print_payload(payload)

def parse_ipv6_hop(data):
    next_header = data[:2]
    length = data[2:4]
    limit = 16 + (int(length, 16) * 2) # length counts from after the 8th byte
    options = data[4:limit]
    payload = data[limit:]

    print("IPv6 Hop-by-Hop Option Header:")
    print_as_int(next_header, "Next Header:")
    print_as_int(length, "Length:")
    print(f"  {'Options/Padding:':<25} {options}")

    match int(next_header, 16):
        case 0:
            parse_ipv6_hop(payload)
        case 6:
            parse_tcp_header(payload)
        case 17:
            parse_udp_header(payload)
        case 43:
            parse_ipv6_routing(payload)
        case 58:
            parse_icmpv6_header(payload)
        case _:
            print_payload(payload)

def parse_ipv6_routing(data):
    next_header = data[:2]
    length = data[2:4]
    rtype = data[4:6]
    seg_left = data[6:8]
    limit = 16 + (int(length, 16) * 2) # length counts from after the 8th byte
    options = data[8:limit]
    payload = data[limit:]

    print("IPv6 Routing Header:")
    print_as_int(next_header, "Next Header:")
    print_as_int(length, "Length:")
    print_as_int(rtype, "Routing Type:")
    print_as_int(seg_left, "Segments Left:")
    print(f"  {'Options/Padding:':<25} {options}")

    match int(next_header, 16):
        case 0:
            parse_ipv6_hop(payload)
        case 6:
            parse_tcp_header(payload)
        case 17:
            parse_udp_header(payload)
        case 43:
            parse_ipv6_routing(payload)
        case 58:
            parse_icmpv6_header(payload)
        case _:
            print_payload(payload)

def parse_tcp_header(hex_data):
    source_port = hex_data[:4]
    dest_port = hex_data[4:8]
    seq_num = hex_data[8:16]
    ack_num = hex_data[16:24]
    data_offset = hex_data[24:25]
    flags = hex_data[25:28]
    wind_sz = hex_data[28:32]
    checksum = hex_data[32:36]
    urgent = hex_data[36:40]

    # calculate options
    # tcp header is between 20 + upto 40 bytes of options / padding
    header_len = int(data_offset, 16) * 4
    options = hex_data[40:header_len*2]

    payload = hex_data[header_len*2:]

    print("TCP Header:")
    print_as_int(source_port, "Source Port:")
    print_as_int(dest_port, "Destination Port:")
    print_as_int(seq_num, "Sequence Number:")
    print_as_int(ack_num, "Acknowledgement Number:")
    print(f"  {'Data Offset':<25} {data_offset:<20} | {header_len} bytes")
    print_tcp_flags(flags)
    print_as_int(wind_sz, "Window Size:")
    print_as_int(checksum, "Checksum:")
    print_as_int(urgent, "Urgent Pointer:")
    print_as_int(options, "Options:")

    if int(source_port, 16) == 53 or int(dest_port, 16) == 53:
        parse_dns_header(payload)
    else:
        print_payload(payload)

def parse_udp_header(hex_data):
    source_port = hex_data[:4]
    dest_port = hex_data[4:8]
    length = hex_data[8:12]
    checksum = hex_data[12:16]
    payload = hex_data[16:]

    print("UDP Header:")
    print_as_int(source_port, "Source Port:")
    print_as_int(dest_port, "Destination Port:")
    print_as_int(length, "Length:")
    print_as_int(checksum, "Checksum:")

    if int(source_port, 16) == 53 or int(dest_port, 16) == 53:
        parse_dns_header(payload)
    else:
        print(f"  {'Payload (hex):':<25} {payload}")

def parse_dns_header(hex_data):
    trans_id = hex_data[:4]
    flags = hex_data[4:8]
    num_questions = hex_data[8:12]
    num_answers = hex_data[12:16]
    auth = hex_data[16:20]
    additional = hex_data[20:24]
    data = hex_data[24:]

    print("DNS Header:")
    print_as_int(trans_id, "Transaction ID:")
    print_dns_flags(flags)
    print_as_int(num_questions, "Questions:")
    print_as_int(num_answers, "Answers:")
    print_as_int(auth, "Authority RRs:")
    print_as_int(additional, "Additional RRs:")

    answers_index, qname = print_dns_questions(data)
    answers_index += 24
    if int(num_answers, 16) > 0:
        print("  Answers:")
        for i in range(int(num_answers, 16)):
            data = hex_data[answers_index:]
            answers_index += print_dns_answers(data, qname)

def parse_icmp_header(hex_data):
    type_val = int(hex_data[:2], 16)
    type_str = ""
    code_val = int(hex_data[2:4], 16)
    code_str = ""
    checksum = hex_data[4:8]
    extended = hex_data[8:16]   #used to point out any issues in IP message
    payload = hex_data[16:]
    info = {
        1: {"t": "Echo reply", "c": [""]},
        3: {
            "t": "Destination unreachable",
            "c": ["Destination network unreachable",
                  "Destination host unreachable",
                  "Destination protocol unreachable",
                  "Destination port unreachable",
                  "Fragmentation is needed and the DF flag set",
                  "Source route failed"]
        },
        5: {
            "t": "Redirect message",
            "c": ["Redirect the datagram for the network",
                  "Redirect datagram for the host",
                  "Redirect the datagram for the Type of Service and Network",
                  "Redirect datagram for the Service and Host"]
        },
        8: {"t": "Echo request", "c": [""]},
        9: {"t": "Router advertisement", "c": [""]},
        10: {"t": "Router solicitation", "c": [""]},
        11: {
            "t": "Time exceeded",
            "c": ["Time to live exceeded in transit",
                  "Fragment reassembly time exceeded"]
        },
        12: {
            "t": "Parameter problem",
            "c": ["The pointer indicated an error",
                  "Missing required option",
                  "Bad length"]
        },
        13: {"t": "Timestamp", "c": [""]},
        14: {"t": "Timestamp reply", "c": [""]}
    }

    print(f"ICMP Header:")

    if type_val in info:
        type_str = info[type_val]['t']
        if code_val < len(info[type_val]['c']):
            code_str = info[type_val]['c'][code_val]
    print(f"  {'Type:':<25} {hex_data[:2]:<20} | {type_val} ({type_str})")
    print(f"  {'Code:':<25} {hex_data[2:4]:<20} | {code_val} ({code_str})")
    print_as_int(checksum, "Checksum:")
    if int(extended, 16) == 0:
        print(f"  {'Unused:':<25} {extended:<20} | {bin(int(extended, 16))}")
    else:
        print_as_int(extended, "Extended Header:")
    print_payload(payload)

def parse_icmpv6_header(data):
    type_val = int(data[:2], 16)
    type_str = ""
    code_val = int(data[2:4], 16)
    code_str = ""
    checksum = data[4:8]
    payload = data[8:]
    info = {
        1: {
            "t": "Destination Unreachable",
            "c": ["No route to destination",
                  "Communication with destination administratively prohibited",
                  "Beyond scope of source address",
                  "Address unreachable",
                  "Port unreachable",
                  "Source address failed ingress/egress policy",
                  "Reject route to destination",
                  "Error in source routing header",
                  "Headers too long",
                  "Error in P-route"]
        },
        2: {"t": "Packet Too Big", "c": [""]},
        3: {
            "t": "Time Exceeded",
            "c":["Hop limit exceeded in transit", "Fragment reassembly time exceeded"]
        },
        4: {
            "t": "Parameter Problem",
            "c": ["Erroneous header field encountered",
                  "Unrecognized Next Header type encountered",
                  "IPv6 First Fragment has incomplete IPv6 Header Chain",
                  "SR Upper-layer Header Error",
                  "Unrecognized Next Header type encountered by intermediate node",
                  "Extension header too big",
                  "Extension header chain too long",
                  "Too many extension headers",
                  "Too many options in extension header",
                  "Option too big"]
        },
        128: {"t": "Echo Request", "c": [""]},
        129: {"t": "Echo Reply", "c": [""]},
        130: {"t": "Multicast Listener Query", "c": [""]},
        131: {"t": "Multicast Listener Report", "c": [""]},
        132: {"t": "Multicast Listener Done", "c": [""]},
        133: {"t": "Router Solicitation", "c": [""]},
        134: {"t": "Router Advertisement", "c": [""]},
        135: {"t": "Neighbor Solicitation", "c": [""]},
        136: {"t": "Neigbor Advertisement", "c": [""]},
        137: {"t": "Redirect Message", "c": [""]},
        138: {
            "t": "Router Renumbering",
            "c": ["Router Renumbering Command",
                  "Router Renumbering Result"]
        },
        139: {
            "t": "ICMP Node Information Query",
            "c": ["The Data field contains an IPv6 address",
                  "The Data field contains a name",
                  "The Data field contains an IPv4 address"]
        },
        140: {
            "t": "ICMP Node Information Response",
            "c": ["A successful reply",
                  "The Responder refuses to supply the answer",
                  "The Qtype of the Query is unknown to the Responder"]
        },
        141: {"t": "Inverse Neighbor Discovery", "c": [""]},
        142: {"t": "Inverse Neighbor Discovery", "c": [""]},
        144: {"t": "Home Agent Address Discovery", "c": [""]},
        145: {"t": "Home Agent Address Discovery", "c": [""]},
        146: {"t": "Mobile Prefix Solicitation", "c": [""]},
        147: {"t": "Mobile Prefix Advertisement", "c": [""]},
        157: {
            "t": "Duplicate Address Request Code Suffix",
            "c": ["DAR message",
                  "EDAR message with 64-bit ROVR field",
                  "EDAR message with 128-bit ROVR field",
                  "EDAR message with 192-bit ROVR field",
                  "EDAR message with 256-bit ROVR field",
                  "","","","","","","","","","",""] # Unassigned
        },
        158: {
            "t": "Duplicate Address Confirmation Code Suffix",
            "c": ["DAC message",
                  "EDAC message with 64-bit ROVR field",
                  "EDAC message with 128-bit ROVR field",
                  "EDAC message with 192-bit ROVR field",
                  "EDAC message with 256-bit ROVR field",
                  "","","","","","","","","","",""] # Unassigned
        },
        160: {
            "t": "Extended Echo Request",
            "c": ["No Error"]
        },
        161: {
            "t": "Extended Echo Reply",
            "c": ["No Error",
                  "Malformed Query",
                  "No Such Interface",
                  "No Such Table Entry",
                  "Multiple Interfaces Satisfy Query"]
        }
    }

    print("ICMPv6 Header:")

    if type_val in info:
        type_str = info[type_val]['t']
        if code_val < len(info[type_val]['c']):
            code_str = info[type_val]['c'][code_val]
    print(f"  {'Type:':<25} {data[:2]:<20} | {type_val} ({type_str})")
    print(f"  {'Code:':<25} {data[2:4]:<20} | {code_val} ({code_str})")

    print_as_int(checksum, "Checksum:")
    print_payload(payload)

