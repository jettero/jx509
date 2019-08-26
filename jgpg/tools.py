# coding: utf-8

import gnupg

def list_():
    gpg = gnupg.GPG()
    private_keys = gpg.list_keys(True)
    for keydict in private_keys:
        uids = ', '.join(keydict['uids'])
        print(f'uids: {uids}; keyid: {keydict["keyid"]}')

def sign(targets):
    print(f'TODO sign: {targets}')
