def bin_split(filename):
    bin_file = open(filename, "rb")
    raw_bytes = bin_file.read()
    # Split the message into 223 bytes per group.
    n = 223
    data_list = [raw_bytes[i:i+n] for i in range(0, len(raw_bytes), n)]
    # If the last group shorter than 223 bytes, add zero-bytes for padding.
    last = len(raw_bytes) % n
    if last != 0:
        padding = b'0' * (n - last)
        data_list[-1] = data_list[-1] + padding
    bin_file.close()
    return data_list, last

def del_padding(filename, num_bytes):
    with open(filename, 'rb') as file:
        file.seek(0, 2) 
        file_size = file.tell()
    new_size = max(file_size - num_bytes, 0)
    with open(filename, 'ab') as file:
        file.truncate(new_size)

def bin_collect(decdata, cw_cnt, last):
    collect_data = b''
    for i in range(cw_cnt - 1):
        collect_data = collect_data + decdata[i]
    collect_data = collect_data + decdata[cw_cnt - 1][:last]
    return collect_data

def reader(filename, chunksize):
    data_list = []
    padding = 0
    bin_file = open(filename, "rb")
    while True:
        chunk = bin_file.read(chunksize)
        length = len(chunk)
        if length == chunksize:
            data_list.append(chunk)
        elif length == 0:
            break
        else:
            padding = chunksize - length
            chunk = chunk + (b'0' * padding)
            data_list.append(chunk)
            break
    bin_file.close()
    return data_list, padding


def generate(filename, collect_data):
    bin_file = open(filename, 'wb+')
    bin_file.write(collect_data)
    bin_file.close()
    return True
