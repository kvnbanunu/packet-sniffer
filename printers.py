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
    print(f"    {'Data Length:':<15} {dlen:<8} | {int(dlen, 16)} bytes")
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
                res += ":"
            else:
                res += ":0"
        else:
            #check if previous segment was all 0s, then disable future ::
            if double_colon == False and zero_flag == True:
                double_colon = True
            zero_flag = False
            res += f":{temp.lstrip('0')}"
    print(f"  {label:<25} {data:<20} | {res}")

def print_as_int(data, label):
    as_int = int(data, 16)
    print(f"  {label:<25} {data:<20} | {as_int}")

def print_payload(data):
    print(f"  {'Payload (hex):':<25} {data}")
