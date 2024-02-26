def bin_split(filename):
    bin_file = open(filename, "rb")
    raw_bytes = bin_file.read()
    n = 223 # Split the message into 223 bytes per group.
    msglist = [raw_bytes[i:i+n] for i in range(0, len(raw_bytes), n)]
    cnt = len(msglist)
    if len(raw_bytes) % n != 0: # If the last group shorter than 223 bytes, add zero-bytes for padding.
        last = len(msglist[cnt-1])
        addzero = b'0' * (n - last)
        msglist[cnt-1] = msglist[cnt-1] + addzero
    bin_file.close()
    return msglist, cnt, last
