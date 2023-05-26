def bin_split(filename):
    bin_file = open(filename, "rb")
    raw_bytes = bin_file.read()
    n = 255 # Split the message into groups
    msglist = [raw_bytes[i:i+n] for i in range(0, len(raw_bytes), n)]
    return msglist
