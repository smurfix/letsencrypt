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
        except OSError:
            return 0
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    d = cert.get_notAfter()
    d = datetime.strptime(date,"%Y%m%d%H%M%SZ")
    import pdb;pdb.set_trace()
    d -= epoch
    return td.days*86400 + td.seconds + td.microseconds/10**6

    
def get_cert(domain, handler, lifetime=24*3600, path="/etc/letsencrypt/keys"):
    """\
        Returns the (certificate,key,expiry) filename pair for `domain`.
        `path` is where the secrets are kept.
        `handler` is a two-argument function(name,data) which arranges to
        serve `data` at http://`domain`/.well-known/acme-challenge/`name`.
        When `data` is `None`, the file should no longer be server.

        `lifetime` is the minimum lifetime of an existing certificate. If
        it expires after that many seconds, it will be returned as-is,
        otherwise a new cert will be generated.
        `expiry` is the time in seconds after which the key will expire.
        You should 
        """
    pem = os.path.join(path, domain)+".pem"
    key = os.path.join(path, domain)+".key"
    csr = os.path.join(path, domain)+".csr"

    t = get_lifetime(pem)-time.time()-lifetime
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
    key_auth = acme.token2file(master_key, challenge['token'], args.acme_dir)
    handler(challenge['token'],key_auth)

    acme.challenge_done(key, challenge['uri'], key_auth)
    acme.wait_verification(challenge['uri'])
    result = acme.get_certificate(key, csr)

    with open(os.path.join(path, domain)+".crt", "wt") as f:
        f.write(result)

    with open(pem, "wt") as f:
        ipath = os.path.join(path, "intermediate.pem")
        t = get_lifetime(ipath)
        if t-time.time() < lifetime:
            r = requests.get("https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem")
            i = r.text
            with open(ifile,'wt') as t:
                t.write(i)
        else:
            with open(ifile,'rt') as t:
                i = t.read()
        f.write(i)
        f.write(result)

    handler(challenge['token'])
    return pem,

