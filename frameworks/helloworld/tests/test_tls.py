import pytest

import sdk_cmd as cmd
import sdk_install as install
import sdk_plan as plan
import sdk_utils
from tests.config import (
    PACKAGE_NAME
)


def setup_module(module):
    install.uninstall(PACKAGE_NAME)
    cmd.run_cli("package install --cli dcos-enterprise-cli")


def teardown_module(module):
    install.uninstall(PACKAGE_NAME)


def create_service_account(name, secret_name=None):
    """
    Creates a service account, a secret containing private key and uid and
    assigns `superuser` permissions to the account.

    Args:
        name (str): Name of the user account
        secret_name (str): Optionally name of secret. If not provided service
            account name will be used.
    """
    if secret_name is None:
        secret_name = name

    cmd.run_cli(
        "security org service-accounts keypair private-key.pem public-key.pem")
    cmd.run_cli(
        'security org service-accounts create -p public-key.pem '
        '-d "My service account" {name}'.format(
            name=name)
        )
    cmd.run_cli(
        "security secrets create-sa-secret private-key.pem "
        "{name} {secret_name}".format(
            name=name,
            secret_name=secret_name)
        )
    # TODO(mh): Fine grained permissions needs to be addressed in DCOS-16475
    cmd.run_cli(
        "security org groups add_user superusers {name}".format(name=name))


def delete_service_account(name, secret_name=None):
    """
    Deletes service account and secret with private key that belongs to the
    service account.

    Args:
        name (str): Name of the user account
        secret_name (str): Optionally name of secret. If not provided service
            account name will be used.
    """
    if secret_name is None:
        secret_name = name

    cmd.run_cli(
        "security org service-accounts delete {name}".format(name=name))
    cmd.run_cli(
        "security secrets delete {secret_name}".format(secret_name=secret_name))


@pytest.fixture()
def service_account():
    """
    Creates service account with `hello-world` name and yields the name.
    """
    name = 'hello-world'
    create_service_account(name)
    yield name
    delete_service_account(name)


@pytest.fixture()
def cleanup_service_leftover():
    install.uninstall(PACKAGE_NAME)


def test_tls_basics(service_account):
    install.install(
        PACKAGE_NAME,
        running_task_count=1,
        service_name=service_account,
        additional_options={
            "service": {
                "spec_file": "examples/tls.yml",
                "secret_name": service_account,
                "principal": service_account,
                },
            }
        )

    deployment_plan = plan.get_deployment_plan(PACKAGE_NAME)
    sdk_utils.out("deployment_plan: " + str(deployment_plan))

    # default is serial strategy, hello deploys first
    # launch will fail if secrets are not available or not accessible
    plan.wait_for_completed_deployment(PACKAGE_NAME)

    install.uninstall(PACKAGE_NAME)
