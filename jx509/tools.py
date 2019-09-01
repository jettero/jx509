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

def cmd_sign(targets, key_file='private.key', **kw):
    for target in targets:
        sign_target(target, f'{target}.sig', key_file=key_file)

def cmd_msign(targets, mfilename='MANIFEST', sfilename='SIGNATURE', **kw):
    manifest(targets, mfilename=mfilename)
    if sfilename in (None, False):
        sfilename = f'{mfilename}.sig'
    sign_target(mfilename, sfilename)


# def verify(targets, mfname='MANIFEST', sfname='SIGNATURE'):
#     gpg = gnupg.GPG()
#     if not sfname:
#         if os.path.isfile('SIGNATURE'):
#             sfname = 'SIGNATURE'
#         elif os.path.isfile(f'{mfname}.sig'):
#             sfname = f'{mfname}.sig'
#         elif os.path.isfile(f'{mfname}.asc'):
#             sfname = f'{mfname}.asc'
#     with open(sfname, 'rb') as sfh:
#         verified = gpg.verify_file(sfh, mfname)
#     if verified.trust_level is not None and verified.trust_level >= verified.TRUST_FULLY:
#         hash_dict = dict()
#         with open(mfname, 'r') as mfh:
#             for line in mfh:
#                 hash,fname = line.strip().split()
#                 hash_dict[fname] = hash
#         def verify_hash(fname):
#             digest = hash_target(fname)
#             if digest != hash_dict[fname]:
#                 raise Exception(f'hash for {fname} does not match signed manifest:\n'
#                     f'     {digest}\n  vs {hash_dict[fname]}')
#         descend_targets(targets, verify_hash)
#     else:
#         raise Exception(f'{mfname} does not match signature in {sfname} or is otherwise not trusted')
