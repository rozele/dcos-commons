import pytest

import sdk_install as install
import sdk_utils as utils
import sdk_networks as networks

from tests.config import (
    PACKAGE_NAME,
    DEFAULT_TASK_COUNT
)


@pytest.fixture(scope='module', autouse=True)
def configure_package(configure_universe):
    try:
        install.uninstall(PACKAGE_NAME)
        utils.gc_frameworks()
        install.install(PACKAGE_NAME, DEFAULT_TASK_COUNT, additional_options=networks.ENABLE_VIRTUAL_NETWORKS_OPTIONS)

        yield # let the test session execute
    finally:
        install.uninstall(PACKAGE_NAME)


@pytest.mark.sanity
@pytest.mark.smoke
@pytest.mark.overlay
def test_install():
    networks.check_task_network("template-0-node")
