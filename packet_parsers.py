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
            print("Not implemented: ipv6")
        case "8808":    #ethernet flow control
            print("Not implemented: ethernet flow control")
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

def print_as_int(data, label):
    as_int = int(data, 16)
    print(f"  {label:<25} {data:<20} | {as_int}")

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

def parse_icmp_header(hex_data):
    type_val = int(hex_data[:2], 16)
    code_val = int(hex_data[2:4], 16)
    checksum = hex_data[4:8]
    extended = hex_data[8:16]   #used to point out any issues in IP message
    info = {
        1: {
            "t": "Echo reply",
            "c": ["Echo reply"]
        },
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
        8: {
            "t": "Echo request",
            "c": ["Echo request"]
        },
        9: {
            "t": "Router advertisement",
            "c": ["User to discover the addresses of operational routers"]
        },
        10: {
            "t": "Router solicitation",
            "c": ["User to discover the addresses of operational routers"]
        },
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
        13: {
            "t": "Timestamp",
            "c": ["Used for time synchronization"]
        },
        14: {
            "t": "Timestamp reply",
            "c": ["Reply to Timestamp message"]
        }
    }

    print(f"ICMP Header:")
    print(f"  {'Type:':<25} {hex_data[:2]:<20} | {type_val} ({info[type_val]['t']})")
    print(f"  {'Code:':<25} {hex_data[2:4]:<20} | {code_val} ({info[type_val]['c'][code_val]})")
    print_as_int(checksum, "Checksum:")
    if int(extended, 16) == 0:
        print(f"  {'Unused:':<25} {extended:<20} | {bin(int(extended, 16))}")
    else:
        print_as_int(extended, "Extended Header:")
    print(f"  {'Payload (hex):':<25} {hex_data[16:]}")

def print_tcp_flags(data):
    as_bin = f"{int(data, 16):0{12}b}" # keep leading 0s / 12 bits
    res = as_bin[:3]
    flags = as_bin[3:]
    labels = ["Accurate ECN:", "Congestion Window Reduced:", "ECN-Echo:", "Urgent:",
              "Acknowledgement:", "Push:", "Reset:", "Syn:", "Fin:"]

    print(f"  {'Reserved:':<25} 0b{res:<18} | {int(res, 2)}")
    print(f"  {'Flags':<25} 0b{flags:<18} | {int(flags, 2)}")
    for i in range(9):
        setflag = "Set" if flags[i] == "1" else "Not Set"
        print(f"    {labels[i]:<30} {flags[i]} | {setflag}")

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

    if int(source_port, 16) == 53:
        parse_dns_header(payload)
    else:
        print(f"  {'Payload (hex):':<25} {payload}")

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

    if int(source_port, 16) == 53:
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

# helper function to parse the dns question.
# Returns index for answers and qname for reuse
def print_dns_questions(data):
    index = 0
    labels = []

    while data[index:index+2] != "00":
        length = int(data[index:index+2], 16) * 2
        index += 2
        labels.append(bytes.fromhex(data[index:index+length]).decode('ascii'))
        index += length

    qname = ".".join(labels) # add '.' inbetween each label

    index += 2 # move past '00'
    qtype = data[index:index+4]
    index += 4
    qclass = data[index:index+4]
    index += 4

    print(f"  {'Queries:':<25} {data[:index]}")
    print(f"    {'Name:':<10} {qname}")
    print(f"    {'Type:':<10} {qtype} | {int(qtype, 16)}")
    print(f"    {'Class:':<10} {qclass} | {int(qclass, 16)}")
    
    return index, qname

def print_dns_answers(data, name):
    atype = data[4:8]
    aclass = data[8:12]
    ttl = data[12:20]
    dlen = data[20:24]
    index = 24 + (int(dlen, 16) * 2)
    adata = data[24:index]

    print(f"    {'Name:':<15} {name:<8}")
    print(f"    {'Type:':<15} {atype:<8} | {int(atype, 16)}")
    print(f"    {'Class:':<15} {aclass:<8} | {int(aclass, 16)}")
    print(f"    {'Time To Live:':<15} {ttl:<8} | {int(ttl, 16)} seconds")
    print(f"    {'Data Length:':<15} {dlen} | {int(dlen, 16)} bytes")
    print(f"    {'Data (hex):':<15} {adata}")

    return index

def print_dns_flags(data):
    as_bin = f"{int(data, 16):0{16}b}" # keep leading 0s / 16 bits
    res = as_bin[:1]
    opcode = as_bin[1:5]
    auth = as_bin[5:6]
    trunc = as_bin[6:7]
    rec_des = as_bin[7:8]
    rec_avail = as_bin[8:9]
    z = as_bin[9:10]
    ans_auth = as_bin[10:11]
    non_auth = as_bin[11:12]
    reply = as_bin[12:16]

    isResponse = int(res, 2) == 1

    resStr = "Message is a Response" if isResponse else "Message is a Query"

    print(f"  {'Flags:':<25} {data:<20} | 0b{as_bin}")
    print(f"    {'Response:':<25} 0b{res:<4} | {int(res, 2)} ({resStr})")
    print(f"    {'Opcode:':<25} 0b{opcode:<4} | {int(opcode, 2)}")
    if isResponse:
        print(f"    {'Authoritative:':<25} 0b{auth:<4} | {int(auth, 2)}")
    print(f"    {'Truncated:':<25} 0b{trunc:<4} | {int(trunc, 2)}")
    print(f"    {'Recursion Desired:':<25} 0b{rec_des:<4} | {int(rec_des, 2)}")
    if isResponse:
        print(f"    {'Recursion Available:':<25} 0b{rec_avail:<4} | {int(rec_avail, 2)}")
    print(f"    {'Z:':<25} 0b{z:<4} | {int(z, 2)}")
    if isResponse:
        print(f"    {'Answer Authenticated:':<25} 0b{ans_auth:<4} | {int(ans_auth, 2)}")
    print(f"    {'Non-Authenticated Data:':<25} 0b{non_auth:<4} | {int(non_auth, 2)}")
    if isResponse:
        print(f"    {'Reply Code:':<25} 0b{reply:<4} | {int(reply, 2)}")

# helper func for ipv4 header flags
def print_ipv4_flags(data):
    as_bin = f"{int(data, 16):0{16}b}" # keep leading 0s / 16 bits
    labels = ["Reserved:", "DF (Do not Fragment):", "MF (More Fragments):"]

    print(f"  {'Flags & Frag Offset:':<25} {data:<20} | 0b{as_bin}")
    for i in range(3):
        print(f"    {labels[i]:<25} {as_bin[i]}")
    print(f"    {'Fragment Offset:':<25} {hex(int(as_bin[3:], 2))} | {int(as_bin[3:], 2)}")

# helper func for ipv4 header differential services
def print_diff_services(data):
    as_bin = f"{int(data, 16):0{8}b}" # keep leading zeros
    codepoint = as_bin[:6] # first 6 digits
    congestion = as_bin[6:] # last 2 digits

    print(f"  {'Differentiated Services:':<25} {data:<20} | 0b{as_bin}")
    print(f"    {'Differentiated Services Codepoint:':<25} 0b{codepoint} | {int(codepoint, 2)}")
    print(f"    {'Explicit Congestion Notification:':<25} 0b{congestion} | {int(congestion, 2)}")

# convert hex string into mac address format before printing
def print_mac_addr(data, label):
    res = ':'.join(data[i:i+2] for i in range(0, 12, 2))
    print(f"  {label:<25} {data:<20} | {res}")

# convert hex string into ipv4 address format 0.0.0.0 before printing
def print_ipv4_addr(data, label):
    res = f"{int(data[:2], 16)}"
    for i in range(2, 8, 2):
        res += f".{int(data[i:i+2], 16)}"
    print(f"  {label:<25} {data:<20} | {res}")

# convert hex string into ipv6 address format
# ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
# remove any leading zeros in each segment
# unless 0000 -> 0
# segments with only zeros replaced with double colon ::
# double colon can only be used once
def print_ipv6_addr(data, label):
    res = data[:4].lstrip('0')  #strip leading zeros

    double_colon = False #only set to true after returning to non 0 segment after 0 only segment
    zero_flag = False   #true if last iteration was all 0s
    for i in range(4, 32, 4):
        temp = data[i:i+4]
        if int(temp, 16) == 0:  #if all zeros
            if double_colon == False:   #if first instance of ::
                if zero_flag == True:
                    continue    #skip adding more colons
                zero_flag = True
                res += "::"
            else:
                res += ":0"
        else:
            #check if previous segment was all 0s, then disable future ::
            if double_colon == False and zero_flag == True:
                double_colon = True
            zero_flag = False
            res += f":{temp.lstrip('0')}"
    print(f"  {label:<25} {data:<20} | {res}")
