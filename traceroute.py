import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.version = int(b[0:4], 2)
        self.header_len = int(b[4:8], 2) * 4
        self.tos = int(b[8:16], 2)
        self.length = int(b[16:32], 2)
        self.id = int(b[32:48], 2)
        self.flags = int(b[48:51], 2)
        self.frag_offset = int(b[51:64], 2)
        self.ttl = int(b[64:72], 2)
        self.proto = int(b[72:80], 2)
        self.cksum = int(b[80:96], 2)
        self.src = util.inet_ntoa(buffer[12:16])
        self.dst = util.inet_ntoa(buffer[16:20])

    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.type = int(b[0:8], 2)
        self.code = int(b[8:16], 2)
        self.cksum = int(b[16:32], 2)

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.src_port = int(b[0:16], 2)
        self.dst_port = int(b[16:32], 2)
        self.len = int(b[32:48], 2)
        self.cksum = int(b[48:64], 2)

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

def invalid_icmp(icmp_header: ICMP):
    # Test B2: Invalid ICMP Type
    if icmp_header.type == 3 and icmp_header.code == 3:
        return False
        
    #Test B3: Invalid ICMP Code
    if icmp_header.type == 11 and icmp_header.code == 0:
        return False

    return True


def classify_packets(buffer: bytes):  
    #Test B6: Truncuated Buffer
    if len(buffer) < 20:
        return None, None

    ip_header = IPv4(buffer)
    
    #Test B4: Invalid IP Protocal
    if ip_header.proto != 1:
        return None, None
    
    #Test B6: Truncuated Buffer : (actual header length different from header length field)
    if ip_header.header_len < 20 or len(buffer) < ip_header.header_len:
        return None, None
    
    #Test B6: Truncuated Buffer : Make sure to parse ICMP from bytes that exist
    if len(buffer) < ip_header.header_len + 8:
        return None, None
    
    icmp_header = ICMP(buffer[ip_header.header_len: ip_header.header_len + 8])

    if invalid_icmp(icmp_header): 
            return None, None
    
    # ICMP Payload contains ORIGINAL packet sent back by router causing error alongside UDP packet header
    icmp_playload = buffer[ip_header.header_len + 8:]
    
    #Test B5: Unparsable Response & Test B6 Truncuated Buffer
    if len(icmp_playload) < 20:
        return None, None 

    payload_ip = IPv4(icmp_playload)
    
    #Test B7: Irrelevant UDP Response
    if payload_ip.proto != 17:
        return None, None
        
    return ip_header, icmp_header

def ignore_packet(buffer: bytes):
    ip_header, icmp_header = classify_packets(buffer)
    if ip_header and icmp_header:
        return False
    return True

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    # TODO Add your implementation
    #Test B9: Router Loops
    prev_seen_routers = list()
    prev_seen_probes = set()
    port = TRACEROUTE_PORT_NUMBER
    for ttl in range(1, TRACEROUTE_MAX_TTL+1):
        curr_ttl_routers = set()
        sendsock.set_ttl(ttl)

        for _ in range(PROBE_ATTEMPT_COUNT):
            sendsock.sendto("Potato".encode(), (ip, port))
            port += 1
            if recvsock.recv_select():
                buf, address = recvsock.recvfrom() 
                if not ignore_packet(buf) and buf not in prev_seen_probes:
                    curr_ttl_routers.add(address[0])
                    prev_seen_probes.add(buf)

        util.print_result(list(curr_ttl_routers), ttl)
        prev_seen_routers.append(list(curr_ttl_routers))
        if ip in curr_ttl_routers:
            break


    return prev_seen_routers


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
