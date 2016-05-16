from __future__ import print_function
__version__ = '0.1.4'

import os
import time
import requests

from . import acme
from . import certificate
from . import parser

from OpenSSL import crypto
from datetime import datetime,timedelta

import logging
log = logging.getLogger(__name__)

epoch=datetime(1970,1,1)

def get_lifetime(cert):
    if '\n' not in cert:
        try:
            with open(cert,'rb') as f:
                cert = f.read()
        except (IOError,OSError):
            return 0
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    d = cert.get_notAfter()
    d = datetime.strptime(d,"%Y%m%d%H%M%SZ")
    d -= epoch
    return d.days*86400 + d.seconds + d.microseconds/10**6

    
def get_cert(domain, handler, lifetime=24*3600, path="/etc/letsencrypt/keys"):
    """\
        Returns the (certificate,key,expiry) triple for `domain`.
        `path` is where the secrets are kept.
        `handler` is a two-argument function(name,data) which arranges to
        serve `data` at http://`domain`/.well-known/acme-challenge/`name`.
        When `data` is `None`, the file should no longer be server.

        `lifetime` is the minimum lifetime of the existing certificate. If
        it expires after more than that many seconds, it will be returned
        as-is, otherwise a new cert will be requested.

        `certificate` and `key` are paths to the files containing the
        certificate (including intermediate certs) and the corresponding
        private key.
        `expiry` is the time in seconds after which the certificate should be
        renewed, i.e. the lifetime has already been subtracted. The value
        can thus directly be passed to a suitable delay function.
        
        """
    pem = os.path.join(path, domain)+".pem"
    key = os.path.join(path, domain)+".key"
    csr = os.path.join(path, domain)+".csr"
    crt = os.path.join(path, domain)+".crt"

    t = get_lifetime(crt)-time.time()-lifetime
    if t > 0 and os.path.exists(key):
        return pem,key,t

    master_key = os.path.join(path, "letsencrypt.key")
    if not os.path.isfile(master_key):
        key = certificate.createKeyPair()
        with open(master_key, "wb") as f:
            f.write(certificate.dumpKey(key))

    if not os.path.isfile(key):
        k = certificate.createKeyPair()
        request = certificate.createCertRequest(k, domain)
        with open(key, "wb") as f:
            f.write(certificate.dumpKey(k))

        with open(csr, "wb") as f:
            f.write(certificate.dumpCsr(request))

    master_key = parser.importRSA(master_key)
    csr = parser.importCSR(csr)

    acme.register_account(master_key, log)
    challenge = acme.get_challenge(master_key, domain, log)
    key_auth = acme.token2file(master_key, challenge['token'])
    handler(challenge['token'],key_auth)

    acme.challenge_done(master_key, challenge['uri'], key_auth)
    acme.wait_verification(challenge['uri'])
    result = acme.get_certificate(master_key, csr)

    with open(crt, "wt") as f:
        f.write(result)

    with open(pem, "wt") as f:
        ipath = os.path.join(path, "intermediate.pem")
        t = get_lifetime(ipath)
        if t-time.time() < lifetime:
            r = requests.get("https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem")
            i = r.text
            with open(ipath,'wt') as t:
                t.write(i)
        else:
            with open(ipath,'rt') as t:
                i = t.read()
        f.write(i)
        f.write(result)

    handler(challenge['token'])
    t = get_lifetime(crt)-time.time()-lifetime
    return pem,key,t

