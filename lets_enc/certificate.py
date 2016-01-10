from OpenSSL import crypto

BITS=4096
C="ES"
ST="Madrid"
L="Madrid"
O="Tuxhound"
OU="IT Department"


def createKeyPair():
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, BITS)
    return pkey


def createCertRequest(pkey, name, digest="sha256"):
    req = crypto.X509Req()

    subject = req.get_subject()
    subject.C = C
    subject.ST = ST
    subject.L = L
    subject.O = O
    subject.OU = OU
    subject.CN = name

    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return req


def createCertificate(req, issuerCertKey, serial, validityPeriod, digest="sha256"):
    """
    Generate a certificate given a certificate request.
    Arguments: req        - Certificate request to use
               issuerCert - The certificate of the issuer
               issuerKey  - The private key of the issuer
               serial     - Serial number for the certificate
               notBefore  - Timestamp (relative to now) when the certificate
                            starts being valid
               notAfter   - Timestamp (relative to now) when the certificate
                            stops being valid
               digest     - Digest method to use for signing, default is sha256
    Returns:   The signed certificate in an X509 object
    """
    issuerCert, issuerKey = issuerCertKey
    notBefore, notAfter = validityPeriod
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuerKey, digest)
    return cert

def dumpKey(key):
    return crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

def dumpCsr(csr):
   return crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)

def pem2der(csr):
    return crypto.dump_certificate_request(crypto.FILETYPE_ASN1, csr)

