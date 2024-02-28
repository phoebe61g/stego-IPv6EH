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

def sniff_ip6_dns(s):
    filename = b''
    query_cnt = 0
    pkts_buff = []
    while True:
        frame, addr = s.recvfrom(512) # recv a packet
        if frame[12:14] == b'\x86\xdd': # If it's IPv6 packet.
            pkt = Ether(frame)
            if len(pkts_buff) == 0: # Get filename & cw_cnt & last from the first pkt.
                try:
                    RR = pkt.getlayer(DNS).qd.qname.split(b'.')
                    filename = RR[0] + b'.' + RR[1]
                    cw_cnt = int(RR[2]) 
                    query_cnt = cw_cnt * 16
                    last = int(RR[4])
                    pkts_buff.append(pkt)
                    print("--> Filename: {}".format(filename))
                    print("--> Num of queries expect to recv: {}".format(query_cnt))
                except:
                    continue
            else: # Only get data if it's not the first okt.
                try:
                    if pkt.getlayer(UDP).dport == 53:
                        pkts_buff.append(pkt)
                        print(">>> Packets sniffed: {}".format(len(pkts_buff)), end = '\r')
                        if len(pkts_buff) >= query_cnt:
                            break
                except:
                    continue
    return filename, cw_cnt, pkts_buff, last

def sniff_ip6(s, start, timelimit):
    frame_buff = []
    while (time.time() - start) < timelimit:
        frame, addr = s.recvfrom(512)
        if frame[12:14] == b'\x86\xdd': # Filter for IPv6
             frame_buff.append(frame)
    return frame_buff

'''
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
'''
