# coding: utf-8

import sys, os
import click
import jx509.tools

cmds = ['help']
for item in dir(jx509.tools):
    if item.startswith('cmd_') and callable(getattr(jx509.tools,item)):
        cmds.append(item[4:])

@click.command()
@click.option('--debug', is_flag=True, default=False)
@click.option('--version', is_flag=True, default=False)
@click.argument('action', default='msign', type=click.Choice(cmds))
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

    fname = f'cmd_{action}'

    if action == 'help':
        help()

    elif hasattr(jx509.tools, fname):
        getattr(jx509.tools, fname)(targets)

    else:
        raise Exception(f'"{action}" not understood')

    sys.exit(0)
