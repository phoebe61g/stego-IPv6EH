from scapy.all import *
def src_addrs():
    clientMAC = bytes.fromhex(get_if_hwaddr(conf.iface).replace(':',''))
    clientIP = get_if_addr6(conf.iface)
    return clientMAC, clientIP

def dst_addrs():
    #dnsMAC = b'\x00\x0c\x29\xb6\xa7\xcb'
    #dnsIP = '2001:e10:6840:22:20c:29ff:feb6:a7cb'
    dnsMAC = b'\x02\xf3\x6a\x25\xe5\xa7'
    dnsIP = '2406:da1c:d67:ab00:d463:4690:a14d:f111'
    return dnsMAC, dnsIP
