#!/usr/bin/env python

import argparse
import logging
import os
import certificate
import acme
import parser


def main():
    log = logging.getLogger(__name__)
    log.addHandler(logging.StreamHandler())
    log.setLevel(logging.INFO)

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--path", required=True, help="Path where certificate files are/will be stored")
    arg_parser.add_argument("--domain", required=True, help="Domain used")
    arg_parser.add_argument("--acme-dir", required=True, help="path to the .well-known/acme-challenge/ directory")

    args = arg_parser.parse_args()
    
    if not os.path.isfile(os.path.join(args.path, "letsencrypt.key")):
        key = certificate.createKeyPair()
        with open(os.path.join(args.path, "letsencrypt.key"), "wt") as fich:
            fich.write(certificate.dumpKey(key))

    if not os.path.isfile(os.path.join(args.path, args.domain)+".key"):
        key = certificate.createKeyPair()
        request = certificate.createCertRequest(key, args.domain)
        with open(os.path.join(args.path, args.domain) + ".key", "wt") as fich:
            fich.write(certificate.dumpKey(key))

        with open(os.path.join(args.path, args.domain) + ".csr", "wt") as fich:
            fich.write(certificate.dumpCsr(request))

    key = parser.importRSA(os.path.join(args.path, "letsencrypt.key"))
    csr = parser.importCSR(os.path.join(args.path, args.domain)+".csr")

    acme.register_account(key, log)
    challenge = acme.get_challenge(key, args.domain, log)
    key_auth = acme.token2file(key, challenge['token'], args.acme_dir)
    acme.challenge_done(key, challenge['uri'], key_auth)
    acme.wait_verification(challenge['uri'])
    result = acme.get_certificate(key, csr)
    with open(os.path.join(args.path, args.domain)+".crt", "w") as fich:
        fich.write(result)




if __name__ == "__main__":
    main()

