from scapy.all import *
def src_fields():
    clientMAC = get_if_hwaddr(conf.iface).encode()
    clientIP = get_if_addr6(conf.iface)
    return clientMAC, clientIP

def dst_fields():
    # Dst: NCNU Ubuntu DNS Server
    #dnsMAC = b'\x00\x0c\x29\xc3\x6f\xa7'
    #dnsIP = '2001:e10:6841:22:20c:29ff:fec3:6fa7'
    # NCNU another Ubuntu VM
    dnsMAC = b'\x00\x0c\x29\xb6\xa7\xcb'
    dnsIP = '2001:e10:6840:22:20c:29ff:feb6:a7cb'
    return dnsMAC, dnsIP
