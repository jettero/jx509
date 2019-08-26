# coding: utf-8

import os
import getpass
import hashlib
import gnupg

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
    return s256.hexdigest()

def manifest(targets, mfilename='MANIFEST'):
    with open(mfilename, 'w') as mfh:
        for fname in targets:
            if os.path.isfile(fname):
                digest = _hash_target(fname)
                mfh.write(f'{digest} {fname}\n')
            if os.path.isdir(fname):
                for dirpath, dirnames, filenames in os.walk(fname):
                    for fname in filenames:
                        fname_ = os.path.join(dirpath, fname)
                        digest = _hash_target(fname_)
                        mfh.write(f'{digest} {fname_}\n')

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
