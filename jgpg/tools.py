# coding: utf-8

import os
import getpass
import logging
import hashlib
import gnupg

log = logging.getLogger('jgpg.tools')

def list_():
    gpg = gnupg.GPG()
    private_keys = gpg.list_keys(True)
    for keydict in private_keys:
        joined_uids = ', '.join(keydict['uids'])
        print('uids: {juids}; keyid: {keyid} (algo={algo})'.format(
            juids=joined_uids, **keydict))

def _hash_target(fname):
    s256 = hashlib.sha256()
    with open(fname, 'rb') as fh:
        r = fh.read(1024)
        while r:
            s256.update(r)
            r = fh.read(1024)
    hd = s256.hexdigest()
    log.debug(f'hashed {fname}: {hd}')
    return hd

def _descend_targets(targets, cb):
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
            digest = _hash_target(fname)
            mfh.write(f'{digest} {fname}\n')
        _descend_targets(targets, append_hash)

def _sign_target(fname, ofname):
    gpg = gnupg.GPG()
    with open(fname, 'rb') as fh:
        print(f'dropping {fname} signature in {ofname}')
        gpg.sign_file(fh, detach=True, binary=False, output=ofname,
            passphrase=getpass.getpass('passphrase: '))

def msign(targets, mfilename='MANIFEST', sfilename='SIGNATURE'):
    manifest(targets, mfilename=mfilename)
    if sfilename in (None, False):
        sfilename = f'{mfilename}.sig'
    _sign_target(mfilename, sfilename)

def verify(targets, mfname='MANIFEST', sfname='SIGNATURE'):
    gpg = gnupg.GPG()
    if not sfname:
        if os.path.isfile('SIGNATURE'):
            sfname = 'SIGNATURE'
        elif os.path.isfile(f'{mfname}.sig'):
            sfname = f'{mfname}.sig'
        elif os.path.isfile(f'{mfname}.asc'):
            sfname = f'{mfname}.asc'
    with open(sfname, 'rb') as sfh:
        verified = gpg.verify_file(sfh, mfname)
    if verified.trust_level is not None and verified.trust_level >= verified.TRUST_FULLY:
        hash_dict = dict()
        with open(mfname, 'r') as mfh:
            for line in mfh:
                hash,fname = line.strip().split()
                hash_dict[fname] = hash
        def verify_hash(fname):
            digest = _hash_target(fname)
            if digest != hash_dict[fname]:
                raise Exception(f'hash for {fname} does not match signed manifest:\n'
                    f'     {digest}\n  vs {hash_dict[fname]}')
        _descend_targets(targets, verify_hash)
    else:
        raise Exception(f'{mfname} does not match signature in {sfname} or is otherwise not trusted')
