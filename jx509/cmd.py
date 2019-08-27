# coding: utf-8

import sys, os
import click

from jx509.tools import list_, msign, verify

@click.command()
@click.option('--debug', is_flag=True, default=False)
@click.option('--version', is_flag=True, default=False)
@click.argument('action', default='msign', type=click.Choice(['msign', 'list', 'help', 'verify']))
@click.argument('targets', type=click.Path(exists=True), nargs=-1)
def run(action, debug, version, targets):
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

    if action == 'help':
        help()

    elif action == 'msign':
        msign(targets)

    elif action == 'verify':
        verify(targets)

    elif action == 'list':
        list_()

    else:
        raise Exception(f'"{action}" not understood')

    sys.exit(0)
