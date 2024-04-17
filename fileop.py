def bin_split(filename):
    bin_file = open(filename, "rb")
    raw_bytes = bin_file.read()
    # Split the message into 223 bytes per group.
    n = 223
    msglist = [raw_bytes[i:i+n] for i in range(0, len(raw_bytes), n)]
    # If the last group shorter than 223 bytes, add zero-bytes for padding.
    last = len(raw_bytes) % n
    if last != 0:
        padding = b'0' * (n - last)
        msglist[-1] = msglist[-1] + padding
    bin_file.close()
    return msglist, last

def bin_collect(decdata, cw_cnt, last):
    collect_data = b''
    for i in range(cw_cnt - 1):
        collect_data = collect_data + decdata[i]
    collect_data = collect_data + decdata[cw_cnt - 1][:last]
    return collect_data
