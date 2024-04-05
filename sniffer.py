import socket
import time
from scapy.all import *

def sniff_ip6_DstEH(s):
    frame_buff = []
    while True:
        frame, addr = s.recvfrom(512)
        if frame[20] == 60: # next hdr is dst opt eh (protocol num: 60)
            frame_buff.append(frame)
            idle_time = time.time() # renew timer
        else:
            try:
                if time.time() - idle_time > 3: # if idle time > 5 sec
                    break
            except:
                continue
    return frame_buff

def sniff_ip6(s, start, timelimit):
    frame_buff = []
    while (time.time() - start) < timelimit:
        frame, addr = s.recvfrom(512)
        if frame[12:14] == b'\x86\xdd': # Filter for IPv6
             frame_buff.append(frame)
    return frame_buff

def sniff_dns(s):
    cnt = 0
    while True:
        frame, addr = s.recvfrom(512)
        pkt = Ether(frame)
        try:
            dns = pkt.getlayer(DNS)
            ans(pkt, dns)
            cnt += 1
        except:
            continue
    return cnt

def ans(pkt, dns):
    srcIP = pkt.getlayer(IPv6).src
    srcPort = pkt.getlayer(UDP).sport
    dnsID = dns.id
    name = dns.qd.qname
    answer = "10.22." + name.decode('utf-8').split('.')[4] + "." + str(dnsID) 
    print(answer)
    RR = DNS(id=dnsID, qr=1, aa=1, ra=1)
    RR.qd = DNSQR(qname=name)
    RR.an = DNSRR(rrname=name, rdata=answer)
