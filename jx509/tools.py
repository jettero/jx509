# coding: utf-8

import os
import getpass
import logging
import re
import json

from collections import OrderedDict, namedtuple
from Crypto.IO import PEM
from Crypto.Util import asn1
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import OpenSSL.crypto as ossl

log = logging.getLogger(__name__)

class STATUS:
    OK = 'ok'
    FAIL = 'fail'
    VERIFIED = 'verified'
    UNKNOWN = 'unknown'

class X509:
    PEMData = namedtuple('PEMData', ['cert','marker','decrypted'])
    CrtData = namedtuple('CrtData', ['cert','algo','sig'])
    SigData = namedtuple('SigData', ['nonzero_bits','dat', 'algo'])

    def __init__(self, crt_fname, ca_fname):
        self.crt_fname = crt_fname
        self.ca_fname = ca_fname
        with open(ca_fname, 'r') as fh:
            self.ca_raw = fh.read()
        with open(crt_fname, 'r') as fh:
            self.crt_raw = fh.read()

        self.ca = ossl.load_certificate(ossl.FILETYPE_PEM, self.ca_raw)

        ossl_crt = ossl.load_certificate(ossl.FILETYPE_PEM, self.crt_raw)
        self.pdat = self.PEMData(*PEM.decode(self.crt_raw))
        self.cdat = self.CrtData(*asn1.DerSequence().decode(self.pdat.cert))
        _sig = asn1.DerObject().decode(self.cdat.sig).payload
        self.sig = self.SigData(_sig[0], _sig[1:], ossl_crt.get_signature_algorithm().decode())
        self.crt = RSA.importKey(self.pdat.cert)
        self.verifier = PKCS1_v1_5.new(self.crt)

    def verify_cert(self):
        if self.sig.nonzero_bits != 0:
            log.error('The CA cert (%s) may not approve of this certificate (%s): unusual header',
                ca_fname, crt_fname, e)
            return STATUS.UNKNOWN
        try:
            ossl.verify(self.ca, self.sig.dat, self.cdat.cert, self.sig.algo)
            return STATUS.VERIFIED
        except ossl.Error:
            # the error ossl raises is not useful (apparently)
            log.error('The CA cert (%s) does not seem to approve of this certificate (%s)')
        return STATUS.UNKNOWN

MANIFEST_RE = re.compile(r'^\s*(?P<digest>[0-9a-fA-F]+)\s+(?P<fname>.+)$')

def jsonify(obj, indent=2):
    return json.dumps(obj, indent=indent)

def normalize_path(path):
    return os.path.normpath(path)

def hash_target(fname, obj_mode=False):
    s256 = SHA256.new()
    with open(fname, 'rb') as fh:
        r = fh.read(1024)
        while r:
            s256.update(r)
            r = fh.read(1024)
    if obj_mode:
        return s256
    hd = s256.hexdigest()
    log.debug(f'hashed {fname}: {hd}')
    return hd

def descend_targets(targets, cb):
    for fname in targets:
        if os.path.isfile(fname):
            cb(fname)
        if os.path.isdir(fname):
            for dirpath, dirnames, filenames in os.walk(fname):
                for fname in filenames:
                    fname_ = os.path.join(dirpath, fname)
                    cb(fname_)

def manifest(targets, mfname='MANIFEST', output_json=False, **kw):
    # It'd be nice to DRY this somewhat. It's probably not worth it though the
    # non-json form (while super similar) doesn't have to store all the results
    # in ram, it can just write as it goes. Is that better than DRY? ¯\_(ツ)_/¯
    if output_json:
        json_out = OrderedDict()
        def append_hash(fname):
            fname = normalize_path(fname)
            digest = hash_target(fname)
            json_out[fname] = digest
        descend_targets(targets, append_hash)
        with open(mfname, 'w') as mfh:
            mfh.write(jsonify(json_out))
            mfh.write('\n')
    else:
        with open(mfname, 'w') as mfh:
            def append_hash(fname):
                fname = normalize_path(fname)
                digest = hash_target(fname)
                mfh.write(f'{digest} {fname}\n')
            descend_targets(targets, append_hash)

def sign_target(fname, ofname, key_file='private.key', **kw):
    with open(key_file, 'r') as fh:
        private_key = RSA.importKey(fh.read())
    signer = PKCS1_v1_5.new(private_key)
    sig = signer.sign(hash_target(fname, obj_mode=True))
    with open(ofname, 'w') as fh:
        fh.write(PEM.encode(sig, f'Detached Signature of {fname}'))
        fh.write('\n')

def verify_signature(fname, sfname, cert_file='public.crt', ca_fname='ca-root.crt', **kw):
    '''
        Given the fname, sfname cert_file and ca_fnames:

        return STATUS.FAIL if the signature doesn't match
        return STATUS.UNKNOWN if the certificate signature can't be verified with the ca cert
        return STATUS.VERIFIED if both the signature and the CA sig match

    '''
    x509 = X509(cert_file, ca_fname)
    ca_status = x509.verify_cert()
    try:
        with open(sfname, 'r') as fh:
            signature,_,_ = PEM.decode(fh.read()) # also returns header and decrypted-status
    except FileNotFoundError:
        log.error('failed to find %s for %s', sfname, fname)
        return STATUS.UNKNOWN
    if x509.verifier.verify(hash_target(fname, obj_mode=True), signature):
        return ca_status
    log.error('%s failed signature check (%s)', fname, sfname)
    return STATUS.FAIL

def iterate_manifest(mfname):
    with open(mfname, 'r') as fh:
        for line in fh.readlines():
            matched = MANIFEST_RE.match(line)
            if matched:
                _,manifested_fname = matched.groups()
                manifested_fname = normalize_path(manifested_fname)
                yield manifested_fname

def verify_files(targets, mfname='MANIFEST', sfname='SIGNATURE', cert_file='public.crt', output_json=False, **kw):
    ret = OrderedDict()
    ret[mfname] = verify_signature(mfname, sfname=sfname, cert_file=cert_file, **kw)
    # ret[mfname] is the strongest claim we can make about the files we're
    # verifiying if they match their hash in the manifest, the best we can say
    # is whatever is the status of the manifest iteslf.
    digests = OrderedDict()
    while True:
        for target in targets:
            target = normalize_path(target)
            if target in digests or target in (mfname, sfname):
                continue
            digests[target] = STATUS.UNKNOWN
        if digests:
            break
        targets = list(iterate_manifest(mfname))
    with open(mfname, 'r') as fh:
        for line in fh.readlines():
            matched = MANIFEST_RE.match(line)
            if matched:
                digest,manifested_fname = matched.groups()
                manifested_fname = normalize_path(manifested_fname)
                if manifested_fname in digests:
                    digests[manifested_fname] = digest
    for vfname in digests:
        digest = digests[vfname]
        if digest == STATUS.UNKNOWN:
            ret[vfname] = STATUS.UNKNOWN
        elif digest == hash_target(vfname):
            ret[vfname] = ret[mfname]
        else:
            ret[vfname] = STATUS.FAIL
    if output_json:
        print( jsonify(ret) )
    else:
        for vfname,res in ret.items():
            print(f'{vfname}: {res}')
