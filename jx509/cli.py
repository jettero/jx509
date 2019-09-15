# coding: utf-8

import sys, os
import click
import jx509.cmd
from jx509.tools import iterate_manifest

cmds = ['help']
for item in dir(jx509.cmd):
    if item.startswith('cmd_') and callable(getattr(jx509.cmd,item)):
        cmds.append(item[4:])

@click.command()
@click.option('--debug', is_flag=True, default=False)
@click.option('--version', is_flag=True, default=False)
@click.option('-R', '--ca-root-cert', default='ca-root.crt')
@click.option('-p', '--verifying-cert', default='public.crt')
@click.option('-k', '--signing-key', default='private.key')
@click.option('-m', '--manifest-name', default='MANIFEST')
@click.option('-s', '--signature-name', default='SIGNATURE')
@click.option('-j', '--json', is_flag=True, default=False)
@click.argument('action', default='help', type=click.Choice(cmds))
@click.argument('targets', type=click.Path(exists=True), nargs=-1)
def run(action, debug, version, targets, verifying_cert, signing_key,
    manifest_name, signature_name, json, ca_root_cert):
    if version:
        try:
            from jx509.version import version as vstr
        except ModuleNotFoundError:
            if os.path.isfile('./setup.py') and sys.argv[0] == './lrun.py' and os.path.isdir('jx509'):
                # this is relatively unsafe to inflict on unsuspecting users,
                # but I'm relatively careful to make sure it's probably just me
                # running ./lrun.py in my dev dir
                print('running ./setup.py --version')
                os.execvp('./setup.py', ['./setup.py', '--version'])
                from jx509.version import version as vstr
            else:
                raise
        print(f'{vstr} {sys.argv}')
        sys.exit(0)

    if debug:
        import logging
        logging.basicConfig(level=logging.DEBUG)

    fname = f'cmd_{action}'

    if action == 'help':
        help(jx509.cmd)

    elif hasattr(jx509.cmd, fname):
        getattr(jx509.cmd, fname)(
            targets,
            mfname=manifest_name, sfname=signature_name,
            cert_file=verifying_cert, key_file=signing_key,
            ca_fname=ca_root_cert, output_json=json)

    else:
        raise Exception(f'"{action}" not understood')

    sys.exit(0)
