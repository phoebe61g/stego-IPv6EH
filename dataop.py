from scapy.all import *
'''
def convert_frame_pkt(frame_buff):
    pkts_buff = []
    for frame in frame_buff:
        pkt = Ether(frame)
        pkts_buff.append(pkt)
    return pkts_buff
'''
def extract_RR(pkt):
    try:
        RR = pkt.getlayer(DNS).qd.qname.split(b'.')
        filename = RR[0] + b'.' + RR[1]
        cw_cnt = int(RR[2])
        last = int(RR[4])
    except:
        print("RR not found.")
    return filename, cw_cnt, last

def extract_data(frame_buff, cw_cnt):
    data_buff = ([b'0'*16] * 15 + [b'0'*15]) * cw_cnt
    for frame in frame_buff:
        try:
            pkt = Ether(frame)
            # Data
            padn = pkt.getlayer(IPv6ExtHdrDestOpt).options[0]
            data = padn.optdata # 16-bytes
            # Position of data
            RR = pkt.getlayer(DNS).qd.qname.split(b'.')
            dnsID = pkt.getlayer(DNS).id
            index = int(RR[3]) * 16 + dnsID
            # Collect in buffer
            data_buff[index] = data
        except:
            pass
    return data_buff

def find_missing_cw(data_buff):
    for index in range(len(data_buff)):
        if data_buff[index] == b'0':
            print("Missing pkt no.{}".format(index))
    return 0
