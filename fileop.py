def bin_split(filename):
    bin_file = open(filename, "rb")
    raw_bytes = bin_file.read()
    n = 223# Split the message into groups
    msglist = [raw_bytes[i:i+n] for i in range(0, len(raw_bytes), n)]
    cnt = len(msglist)
    if len(raw_bytes) % n != 0:
        num = n - len(msglist[cnt-1])
        add = b'0' * num
        msglist[cnt-1] = msglist[cnt-1] + add
        print(msglist[cnt-1])
    bin_file.close()
    return msglist
