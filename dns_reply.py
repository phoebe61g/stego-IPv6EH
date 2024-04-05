# avg of request-response time: 2393.36 msec
import socket
from scapy.all import *

def ans(pkt):
    dns = pkt[DNS]
    srcIP = pkt[IPv6].src
    srcPort = pkt[UDP].sport
    dnsID = dns.id
    name = dns.qd.qname
    answer = "10.22." + name.decode('utf-8').split('.')[4] + "." + str(dnsID)
    RR = DNS(id=dnsID, qr=1, aa=1, qd = DNSQR(qname=name), an = DNSRR(rrname=name, rdata=answer))
    send(IPv6(dst=srcIP)/UDP(sport=53, dport=srcPort)/RR, verbose=0)

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((str(conf.iface), 0))
while True:
    frame = s.recvfrom(512)[0]
    pkt = Ether(frame)
    if DNS in pkt: 
        ans(pkt)
s.close()
