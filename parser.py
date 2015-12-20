from Crypto.PublicKey import RSA
from binascii import unhexlify
from OpenSSL import crypto


def importRSA(path):
    with open(path) as fich:
        return RSA.importKey(fich.read())


def importCSR(path):
    with open(path) as fich:
        csr = fich.read()
        return crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)


def getModulus(rsa):
    result = "%x" % rsa.n
    return unhexlify("0{0}".format(result) if len(result) % 2 else result)


def getExponent(rsa):
    result = "%x" % rsa.e
    return unhexlify("0{0}".format(result) if len(result) % 2 else result)