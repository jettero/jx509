# coding: utf-8

import os
import getpass
import logging
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

log = logging.getLogger('jx509.tools')

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

def manifest(targets, mfilename='MANIFEST'):
    with open(mfilename, 'w') as mfh:
        def append_hash(fname):
            digest = hash_target(fname)
            mfh.write(f'{digest} {fname}\n')
        descend_targets(targets, append_hash)

def cmd_manifest(targets, mfilename='MANIFEST', **kw):
    manifest(targets, mfilename=mfilename)

def sign_target(fname, ofname, key_file='private.key'):
    with open(key_file, 'r') as fh:
        private_key = RSA.importKey(fh.read())
    signer = PKCS1_v1_5.new(private_key)
    sig = signer.sign(hash_target(fname, obj_mode=True))
    with open(ofname, 'w') as fh:
        fh.write(RSA.PEM.encode(sig, f'Detached Signature of {fname}'))
        fh.write('\n')

def verify_target(fname, ifname, cert_file='public.crt'):
    with open(cert_file, 'r') as fh:
        public_cert = RSA.importKey(fh.read())
    verifier = PKCS1_v1_5.new(public_cert)
    with open(ifile, 'r') as fh:
        signature,_,_ = RSA.PEM.decode(fh.read()) # also returns header and decrypted-status
    if verifier.verify(hash_target(fname, obj_mode=True), signature):
        return True
    return False

def cmd_sign(targets, key_file='private.key', **kw):
    for target in targets:
        sign_target(target, f'{target}.sig', key_file=key_file)

def cmd_msign(targets, mfilename='MANIFEST', sfilename='SIGNATURE', **kw):
    manifest(targets, mfilename=mfilename)
    if sfilename in (None, False):
        sfilename = f'{mfilename}.sig'
    sign_target(mfilename, sfilename)


def verify(targets, mfname='MANIFEST', sfname='SIGNATURE', cert_file='public.crt'):
    if not verify_target(mfname, sfname, cert_file=cert_file):
        return False
    digests = dict()
    for target in targets:
        digests[os.path.abspath(target)] = None
    with open(mfname, 'r') as fh:
        for line in fh.readlines():
            digest,mfname = line.split('  ', 1)
            mfname = os.path.abspath(mfname)
            if mfname in digets:
                digests[mfname] = digest
    for mfname in digests:
        digest = digests[mfname]
        if digest is None or digest != hash_target(mfname):
            return False
    return True
