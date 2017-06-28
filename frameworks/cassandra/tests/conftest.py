import json
import os
import random
import string

import pytest
import shakedown


@pytest.fixture(scope='session')
def configure_universe(request):
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
