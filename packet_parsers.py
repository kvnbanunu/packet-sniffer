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
        case "8809":    #ethernet slow protocol
            print("Not implemented: ethernet slow protocol")
        case "88cc":    #link layer discovery protocol (LLDP)
            print("Not implemented: LLDP")
        case _:
            print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
            print("  No parser available for this EtherType.")

    return ether_type, payload

def conv_mac_addr(data):
    return ':'.join(data[i:i+2] for i in range(0, 12, 2))

def conv_ipv4_addr(data):
    res = f"{int(data[:2], 16)}"
    for i in range(2, 8, 2):
        res += f".{int(data[i:i+2], 16)}"
    return res

def conv_ipv6_addr(data):
    res = f"{int(data[:4], 16)}"
    for i in range(4, 32, 2):
        temp = int(data[i:i+2], 16)
        if temp == 0:
            continue
        res += f"::{temp}"
    return res

# helper func for ipv4 header flags
def print_flags(data):
    as_bin = f"{int(data, 16):0{16}b}" # keep leading zeros
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

# Parse IPv4 header
def parse_ipv4_header(hex_data):
    version = int(hex_data[0], 16)
    header_len = int(hex_data[1], 16) * 4
    diff_services = hex_data[2:4] # call print_diff_services
    total_len = int(hex_data[4:8], 16)
    identification = int(hex_data[8:12], 16)
    flags = hex_data[12:16] # call print_flags
    ttl = int(hex_data[16:18], 16)
    protocol = int(hex_data[18:20], 16)
    checksum = int(hex_data[20:24], 16)
    source_ip = conv_ipv4_addr(hex_data[24:32])
    dest_ip = conv_ipv4_addr(hex_data[32:40])

    print(f"IPv4 Header:")
    print(f"  {'Version:':<25} {hex_data[0]:<20} | {version}")
    print(f"  {'Header Length:':<25} {hex_data[1]:<20} | {header_len} bytes")
    print_diff_services(diff_services)
    print(f"  {'Total Length:':<25} {hex_data[4:8]:<20} | {total_len}")
    print(f"  {'Identification:':<25} {hex_data[8:12]:<20} | {identification}")
    print_flags(flags)
    print(f"  {'Time to Live:':<25} {hex_data[16:18]:<20} | {ttl} hops")
    print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {protocol}")
    print(f"  {'Checksum:':<25} {hex_data[20:24]:<20} | {checksum}")
    print(f"  {'Source IP:':<25} {hex_data[24:32]:<20} | {source_ip}")
    print(f"  {'Destination IP:':<25} {hex_data[32:40]:<20} | {dest_ip}")

    match protocol:
        case 1: #icmp
            print(protocol)
        case 6: #tcp
            print(protocol)
        case 17: #udp
            print(protocol)
        case _:
            print(f"  {'Unsupported Protocol:':<25} {protocol}")

# Parse ARP header
def parse_arp_header(hex_data):
    hardware_type = int(hex_data[:4], 16)
    protocol_type = int(hex_data[4:8], 16)
    hardware_size = int(hex_data[8:10], 16)
    protocol_size = int(hex_data[10:12], 16)
    operation = int(hex_data[12:16], 16)
    sender_mac = conv_mac_addr(hex_data[16:28])
    sender_ip = conv_ipv4_addr(hex_data[28:36])
    target_mac = conv_mac_addr(hex_data[36:48])
    target_ip = conv_ipv4_addr(hex_data[48:56])

    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")
    print(f"  {'Protocol Type:':<25} {hex_data[4:8]:<20} | {protocol_type}")
    print(f"  {'Hardware Size:':<25} {hex_data[8:10]:<20} | {hardware_size}")
    print(f"  {'Protocol Size:':<25} {hex_data[10:12]:<20} | {protocol_size}")
    print(f"  {'Operation:':<25} {hex_data[12:16]:<20} | {operation}")
    print(f"  {'Sender MAC:':<25} {hex_data[16:28]:<20} | {sender_mac}")
    print(f"  {'Sender IP:':<25} {hex_data[28:36]:<20} | {sender_ip}")
    print(f"  {'Target MAC:':<25} {hex_data[36:48]:<20} | {target_mac}")
    print(f"  {'Target IP:':<25} {hex_data[48:56]:<20} | {target_ip}")
