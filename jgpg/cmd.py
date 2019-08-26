#!/usr/bin/env python
# coding: utf-8

import sys, os
import click

@click.command()
@click.option('--version', is_flag=True, default=False)
@click.argument('action', default='sign', type=click.Choice(['sign']))
@click.argument('targets', type=click.Path(exists=True), nargs=-1)
def run(action, version, targets):
    if version:
        try:
            from jgpg.version import version as vstr
        except ModuleNotFoundError:
            if os.path.isfile('./setup.py') and sys.argv[0] == './lrun.py' and os.path.isdir('jgpg'):
                # this is relatively unsafe to inflict on unsuspecting users,
                # but I'm relatively careful to make sure it's probably just me
                # running ./lrun.py in my dev dir
                print('running ./setup.py --version')
                os.execvp('./setup.py', ['./setup.py', '--version'])
                from jgpg.version import version as vstr
            else:
                raise
        print(f'{vstr} {sys.argv}')
        sys.exit(0)

    if action == 'sign':
        print(f'should sign: {targets}')
