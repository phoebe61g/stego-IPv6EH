from scapy.all import *
from config import N, T

def extract_RR(frame):
    pkt = Ether(frame)
    try:
        RR = pkt.getlayer(DNS).qd.qname.split(b'.')
        filename = RR[0] + b'.' + RR[1]
        cw_cnt = int(RR[2])
        pad_bytes = int(RR[4])
    except:
        print("RR not found.")
    return filename, cw_cnt, pad_bytes

def extract_cw(frame_buff, cw_cnt):
    cw_list = ([b'0' * T] * (N//T) + [b'0' * (N%T)]) * cw_cnt
    for frame in frame_buff:
        try:
            pkt = Ether(frame)
            # Get slice
            padn = pkt.getlayer(IPv6ExtHdrDestOpt).options[0]
            slice = padn.optdata
            # Get position of slice
            RR = pkt.getlayer(DNS).qd.qname.split(b'.')
            dnsID = pkt.getlayer(DNS).id
            index = int(RR[3]) * (N//T + 1) + dnsID
            # Store slice in list
            cw_list[index] = slice
        except:
            pass
    return cw_list

'''
def find_missing_cw(data_buff):
    for index in range(len(data_buff)):
        if data_buff[index] == b'0':
            print("Missing pkt no.{}".format(index))
    return 0
'''
