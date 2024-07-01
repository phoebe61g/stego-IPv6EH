from reedsolo import RSCodec, ReedSolomonError
def set_codec(n, k):
    nsym = n - k
    return RSCodec(nsym)

def encoder(orgdata, rsc):
    encdata = rsc.encode(orgdata)
    return encdata

def decoder(rcvdata, rsc):
    decdata = rsc.decode(rcvdata)[0]
    return decdata
