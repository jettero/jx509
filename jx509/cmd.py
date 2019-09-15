# coding: utf-8
'''

The available commands in jx509 are the enumeration callable functions jx509.cmd.cmd_*.

This help is the long help from running 'jx509 help'; see also the short help with 'jx509 --help'.

'''

import logging
from collections import OrderedDict

log = logging.getLogger(__name__)

from jx509.tools import (
    normalize_path, jsonify,
    hash_target,
    sign_target, verify_signature,
    manifest, verify_files,
)

def cmd_hash(targets, output_json=False, **kw):
    '''
    Hash targets and print the result(s) as f'{hash}  {target}'.  If
    ouput_json=True (corresponding to --json in the cli tool): print json
    instead.

    Filenames given as targets are normalized
    '''
    json_out = dict()
    for target in targets:
        target = normalize_path(target)
        hash = hash_target(target)
        if output_json:
            json_out[target] = hash
        else:
            print(f'{hash}  {target}')
    if output_json:
        print(jsonify(json_out))

def cmd_manifest(targets, **kw):
    '''
    Create a manifest of the specified targets and output to mfname
    (corresponding to --mfname in the cli). The MANIFEST (default name) will
    contain roughly the same output as cmd_hash above.
    '''
    manifest(targets, **kw)

def cmd_sign(targets, **kw):
    '''
    Sign target files with a detached signature.  All signatures will drop into
    files with the name f'{target}.sig'. Signing key can be specified with
    --signing-key (corresponding to the key_file kwarg).
    '''
    for target in targets:
        sign_target(target, f'{target}.sig', **kw)

def cmd_verify(targets, output_json=False, **kw):
    '''
    Verify detached signatures of the form f'{target}.sig'.
    '''

    if output_json:
        json_out = OrderedDict()
        for target in targets:
            target = normalize_path(target)
            kw['sfname'] = f'{target}.sig'
            res = verify_signature(target, **kw)
            json_out[target] = res
        print( jsonify(json_out) )
    else:
        for target in targets:
            target = normalize_path(target)
            kw['sfname'] = f'{target}.sig'
            res = verify_signature(target, **kw)
            print(f'{target}: {res}')

def cmd_msign(targets, mfname='MANIFEST', sfname='SIGNATURE', **kw):
    '''
    The ultimate goal of this tool kit is to provide the signed manifest of
    groups of files.  The hashes of all the target files will dump into mfname
    and a detached signature will drop in sfname.
    '''
    manifest(targets, mfname=mfname, **kw)
    if sfname in (None, False):
        sfname = f'{mfname}.sig'
    sign_target(mfname, sfname, **kw)

def cmd_mverify(targets, **kw):
    verify_files(targets, **kw)
