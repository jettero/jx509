# coding: utf-8

import os
import getpass
import logging
import re
from collections import OrderedDict
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

log = logging.getLogger('jx509.tools')

MANIFEST_RE = re.compile(r'^\s*(?P<digest>[0-9a-fA-F]+)\s+(?P<fname>.+)$')

class STATUS:
    OK = 'ok'
    FAIL = 'fail'
    VERIFIED = 'verified'
    UNKNOWN = 'unknown'


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

def cmd_hash(targets, **kw):
    for target in targets:
        target = normalize_path(target)
        hash = hash_target(target)
        print(f'{hash}  {target}')

def descend_targets(targets, cb):
    for fname in targets:
        if os.path.isfile(fname):
            cb(fname)
        if os.path.isdir(fname):
            for dirpath, dirnames, filenames in os.walk(fname):
                for fname in filenames:
                    fname_ = os.path.join(dirpath, fname)
                    cb(fname_)

def manifest(targets, mfname='MANIFEST'):
    with open(mfname, 'w') as mfh:
        def append_hash(fname):
            digest = hash_target(fname)
            mfh.write(f'{digest} {fname}\n')
        descend_targets(targets, append_hash)

def cmd_manifest(targets, mfname='MANIFEST', **kw):
    manifest(targets, mfname=mfname)

def sign_target(fname, ofname, key_file='private.key'):
    with open(key_file, 'r') as fh:
        private_key = RSA.importKey(fh.read())
    signer = PKCS1_v1_5.new(private_key)
    sig = signer.sign(hash_target(fname, obj_mode=True))
    with open(ofname, 'w') as fh:
        fh.write(RSA.PEM.encode(sig, f'Detached Signature of {fname}'))
        fh.write('\n')

def verify_signature(fname, ifname, cert_file='public.crt'):
    with open(cert_file, 'r') as fh:
        public_cert = RSA.importKey(fh.read())
    verifier = PKCS1_v1_5.new(public_cert)
    with open(ifname, 'r') as fh:
        signature,_,_ = RSA.PEM.decode(fh.read()) # also returns header and decrypted-status
    if verifier.verify(hash_target(fname, obj_mode=True), signature):
        return True
    return False

def cmd_sign(targets, key_file='private.key', **kw):
    for target in targets:
        sign_target(target, f'{target}.sig', key_file=key_file)

def cmd_msign(targets, mfname='MANIFEST', sfname='SIGNATURE', **kw):
    manifest(targets, mfname=mfname)
    if sfname in (None, False):
        sfname = f'{mfname}.sig'
    sign_target(mfname, sfname)


def verify_files(targets, mfname='MANIFEST', sfname='SIGNATURE', cert_file='public.crt'):
    ret = OrderedDict()
    ret[mfname] = STATUS.FAIL
    ret[sfname] = STATUS.UNKNOWN
    if not verify_signature(mfname, sfname, cert_file=cert_file):
        return ret
    ret[sfname] = STATUS.OK
    ret[mfname] = STATUS.VERIFIED
    digests = dict()
    for target in targets:
        target = normalize_path(target)
        digests[target] = STATUS.UNKNOWN
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
            ret[vfname] = STATUS.VERIFIED
        else:
            ret[vfname] = STATUS.FAIL
    return ret

def cmd_verify(targets, mfname='MANIFEST', sfname='SIGNATURE', key_file='public.crt'):
    import json
    print( json.dumps(verify_files(targets, mfname=mfname, sfname=sfname, cert_file=key_file), indent=2) )
