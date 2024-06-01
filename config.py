from scapy.all import *
N = 255
K = 223
T = (N - K)//2
Timer = 1

def src_addrs():
    clientMAC = bytes.fromhex(get_if_hwaddr(conf.iface).replace(':',''))
    clientIP = get_if_addr6(conf.iface)
    return clientMAC, clientIP

def dst_addrs():
    #dnsMAC = b'\x02\xf3\x6a\x25\xe5\xa7'
    dnsIP = '2406:da1c:d67:ab00:d463:4690:a14d:f111'
    return dnsIP
