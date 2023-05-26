import socket
import time
from scapy.all import *
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
        try:
            if pkt.getlayer(UDP).dport == 53:
                pkts_buff.append(pkt)
        except:
            pass
    return pkts_buff
