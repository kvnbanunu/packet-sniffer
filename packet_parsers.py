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
    if ether_type == "0806":  # ARP
        parse_arp_header(payload)
    elif ether_type == "0800": # ipv4
        print(ether_type)
    elif ether_type == "86dd": # ipv6
        print(ether_type)
    elif ether_type == "8808": # ethernet flow control
        print(ether_type)
    elif ether_type == "8809": # ethernet slow protocol (LACP)
        print(ether_type)
    elif ether_type == "88cc": # Link Layer Discovery Protocol (LLDP)
        print(ether_type)
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload

def conv_mac_addr(data):
    return ':'.join(data[i:i+2] for i in range(0, 12, 2))

def conv_ipv4_addr(data):
    res = f"{int(data[0:2], 16)}"
    for i in range(2, 8, 2):
        res += f".{int(data[i:i+2], 16)}"
    return res

def conv_ipv6_addr(data):
    res = f"{int(data[0:4], 16)}"
    for i in range(4, 32, 2):
        temp = int(data[i:i+2], 16)
        if temp == 0:
            continue
        res += f"::{temp}"
    return res

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
