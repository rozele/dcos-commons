import json
import os
import random
import string
import sys

import pytest
import shakedown


def out(msg):
    '''Emit an informational message on test progress during test runs'''
    print(msg, file=sys.stderr)

    # I'd much rather the latter, but it is super confusing intermingled with
    # shakedown output.

    ## pytest is awful; hack around its inability to provide a sanely
    ## configurable logging environment
    #current_time = datetime.datetime.now()
    #frames = inspect.getouterframes(inspect.currentframe())
    #try:
    #    parent = frames[1]
    #finally:
    #    del frames
    #try:
    #    parent_filename = parent[1]
    #finally:
    #    del parent
    #name = inspect.getmodulename(parent_filename)
    #out = "{current_time} {name} {msg}\n".format(current_time=current_time,
    #                                             name=name,
    #                                             msg=msg)
    #sys.stderr.write(out)


def gc_frameworks():
    '''Reclaims private agent disk space consumed by Mesos but not yet garbage collected'''
    for host in shakedown.get_private_agents():
        shakedown.run_command(host, "sudo rm -rf /var/lib/mesos/slave/slaves/*/frameworks/*")


def configure_universe(request):
    """Add the universe package repositories defined in $STUB_UNIVERSE_URL.

    This should generally be used as a fixture in a framework's conftest.py:

    @pytest.fixture(scope='session')
    def configure_universe(request):
        utils.configure_universe(request)
    """
    stub_urls = {}

    # prepare needed universe repositories
    stub_universe_urls = os.environ.get('STUB_UNIVERSE_URL')
    if not stub_universe_urls:
        return
    for url in stub_universe_urls.split(' '):
        package_name = 'testpkg-'
        package_name += ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        stub_urls[package_name] = url

    try:
        # clean up any duplicate repositories
        current_universes, _, _ = shakedown.run_dcos_command('package repo list --json')
        for repo in json.loads(current_universes)['repositories']:
            if repo['uri'] in stub_urls.values():
                remove_package_cmd = 'package repo remove {}'.format(repo['name'])
                shakedown.run_dcos_command(remove_package_cmd)

        # add the needed universe repositories
        for name, url in stub_urls.items():
            add_package_cmd = 'package repo add --index=0 {} {}'.format(name, url)
            shakedown.run_dcos_command(add_package_cmd)

        yield # let the test session execute
    finally:
        # clear out the added universe repositores at testing end
        for name, url in stub_urls.items():
            remove_package_cmd = 'package repo remove {}'.format(name)
            shakedown.run_dcos_command(remove_package_cmd)
