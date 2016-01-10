import requests
import json
import base64
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import copy
import parser
import os
import time
from . import certificate
import textwrap

CA = "https://acme-v01.api.letsencrypt.org"


def b64(text):
    return base64.urlsafe_b64encode(text).decode('utf8').replace("=", "")


def get_nonce():
    return requests.get(CA + "/directory").headers['Replay-Nonce']


def _send_signed_request(key, url, payload):
    header = generate_header(key)
    header_copy = copy.deepcopy(header)
    payload = b64(json.dumps(payload).encode('utf8'))
    header_copy['nonce'] = get_nonce()
    header_copy = b64(json.dumps(header_copy).encode('utf8'))
    cipher = PKCS1_v1_5.new(key)
    hash = SHA256.new("{0}.{1}".format(header_copy, payload).encode('utf8'))
    signature = cipher.sign(hash)
    data = json.dumps({
        "header": header, "protected": header_copy,
        "payload": payload, "signature": b64(signature),
    })
    try:
        resp = requests.get(url, data.encode('utf8'))
        return resp.getcode(), resp.read()
    except IOError as e:
        return e.code, e.read()


def generate_header(key):
    mod = parser.getModulus(key)
    exp = parser.getExponent(key)
    return {
        "alg": "RS256",
        "jwk": {
            "e": b64(exp),
            "kty": "RSA",
            "n": b64(mod),
        },
    }


def register_account(key, log):
    log.info("Registering account...")
    code, result = _send_signed_request(key, CA + "/acme/new-reg", {
        "resource": "new-reg",
        "agreement": "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf",
    })
    if code == 201:
        log.info("Registered!")
    elif code == 409:
        log.info("Already registered!")
    else:
        raise ValueError("Error registering: {0} {1}".format(code, result))
    return result


def get_challenge(key, domain, log):
    code, result = _send_signed_request(key, CA + "/acme/new-authz", {
            "resource": "new-authz",
            "identifier": {"type": "dns", "value": domain},
    })
    if code != 201:
        raise ValueError("Error requesting challenges: {0} {1}".format(code, result))
    for chg in json.loads(result.decode('utf8'))['challenges']:
        if chg['type'] == "http-01":
            return chg


def token2file(key, token, path):
    header = generate_header(key)
    account_key = json.dumps(header['jwk'], sort_keys=True, separators=(',', ':'))
    thumbprint = b64(SHA256.new(account_key.encode('utf8')).digest())
    key_auth = "{0}.{1}".format(token, thumbprint)
    path = os.path.join(path, token)
    with open(path, "w") as fich:
        fich.write(key_auth)
    return key_auth


def challenge_done(key, url, keyauth):
    code, result = _send_signed_request(key, url, {
        "resource": "challenge",
        "keyAuthorization": keyauth,
    })
    if code != 202:
        raise ValueError("Error triggering challenge: {0} {1}".format(code, result))
    return result


def wait_verification(url):
    while True:
        try:
            resp = requests.get(url)
            challenge_status = json.loads(resp.read().decode('utf8'))
        except IOError as e:
            raise ValueError("Error checking challenge: {0} {1}".format(
                e.code, json.loads(e.read().decode('utf8'))))
        if challenge_status['status'] == "pending":
            time.sleep(2)
        elif challenge_status['status'] == "valid":
            break
        else:
            raise ValueError("Challenge did not pass: {0}".format(challenge_status))


def get_certificate(key, csr):
   code, result = _send_signed_request(key, CA + "/acme/new-cert", {
        "resource": "new-cert",
        "csr": b64(certificate.pem2der(csr)),
    })
   if code != 201:
       raise ValueError("Error signing certificate: {0} {1}".format(code, result))
   return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(result).decode('utf8'), 64)))
