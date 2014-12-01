"""test_letsencrypt - Functional Test

A series of basic full integration tests to ensure that Letsencrypt is
still running smoothly.

.. note:: This code is not complete nor has it been tested
.. warning:: DO NOT RUN THIS CODE... It very well could mess up your server
.. note:: Do not document this code... it will change quickly

"""

import os
import requests
import shutil
import tarfile
import unittests

from letsencrypt.client import apache_configurator
from letsencrypt.client import CONFIG


# Some of these will likely go into a letsencrypt.tests.CONFIG file
TESTING_DIR = "/var/lib/letsencrypt/testing/"
UBUNTU_CONFIGS = os.path.join(TESTING_DIR, "ubuntu_apache_2_4/")
TEST_BACKUP_DIR = os.path.join(TESTING_DIR, "backup/")
DOC_ROOT_BASE = "/var/www/test_le_"
# I have not put this up on my website yet... it will not work
# This might end up going into the repo... but this is more of
# a user run test as opposed to a Travis CI test.
CONFIG_TGZ_URL = "https://jdkasten.com/letsencrypt/config.tgz"


def setUpModule():
    le_util.make_or_verify_dir(TEST_BACKUP_DIR, 0o755)
    if not os.isdir(UBUNTU_CONFIGS):
        download_unpack_tests()
    backup_apache(TEST_BACKUP_DIR)


def tearDownModule():
    # Should probably restart after this
    swap_config(TEST_BACKUP_DIR)
    apache_restart()


class TwoVhosts_80(unittest.TestCase):
    config_path = os.path.join(UBUNTU_CONFIGS, "two_vhosts_*80/apache2")
    sites_path = os.path.join(UBUNTU_CONFIGS, "two_vhosts_*80/sites")

    def setUp(self):
        swap_config(config_path)

        with open(sites_path, 'rb') as sites_csv:
            sites_reader = csv.reader(sites_csv)
            prep_config(sites_reader)

        apache_restart()

    def test_authenticate_redirect(self):
        cli = client.Client(CONFIG.ACME_SERVER, use_curses=False)
        cli.authenticate("letsencrypt.demo", True, True)

        created_vh = "letsencrypt" + CONFIG.LE_VHOST_EXT
        assert(self._file_enabled(created_vhost))

        f_pre = CONFIG.SERVER_ROOT + "sites-available"
        vhost = apache_configurator.VH(os.path.join(f_pre, created_vh),
                                       "SKIP FOR NOW",
                                       ["*:443"], True, True)

        # TODO Add Validator tests
        assert(self._find_vhost(vhost))
        assert(apache_configurator.check_ssl_loaded())
        assert(self._verify_redirect(os.path.join(f_pre, "letsencrypt.conf")))

    def test_rollback(self):
        pass

    def _file_enabled(self, conf):
        return conf in os.listdir(
            os.path.join(CONFIG.SERVER_ROOT, "sites-enabled"))

    def _find_vhost(self, target):
        for vhost in config.vhosts:
            if (vhost.file == target.file and vhost.addrs == target.addrs and
                    vhost.ssl == target.ssl and
                    vhost.enabled == target.enabled):
                return True
        return False

    def _verify_redirect(self, config_path):
        with open(config_path, 'r') as config_fd:
            conf = config_fd.read()

        return CONFIG.REWRITE_HTTPS_ARGS[1] in conf


def backup_apache(location):
    shutil.copytree(CONFIG.SERVER_ROOT, TEST_BACKUP_DIR)


# Function is to be only used for testing functions in this unittest
def run_tests():
    config_dirs = os.listdir(UBUNTU_CONFIGS)

    for test_bn in config_dirs:
        test_dir = os.path.join(UBUNTU_CONFIGS, test_dir)

        sites_file = os.path.join(test_dir, "sites")

        with open(sites_file, 'rb') as sites_csv:
            sites_reader = csv.reader(sites_csv)
            prep_config(sites_reader)


def add_domain_to_document_root(domain, doc_root):
    try:
        os.mkdir(doc_root, 755)
    except OSError:
        pass
    with open(os.path.join(doc_root, "index.html"), 'w') as html_file:
        html_file.write(domain)


def download_unpack_tests(url=CONFIG_TGZ_URL):
    r = requests.get(url)
    local_tgz_file = os.path.join(TESTING_DIR, 'ubuntu_2_4.tgz')
    with open(local_tgz_file, 'w') as tgz_file:
        tgz_file.write(r.content)

    if tarfile.is_tarfile(local_tgz_file):
        tar = tarfile.open(local_tgz_file)
        tar.extractall()
        tar.close()


def prep_config(sites_reader):
    domain_doc_root = dict()
    counter = 0

    for path, domain in sites_reader:
        if domain in domain_doc_root:
            doc_root = domain_doc_root[domain]
        else:
            domain_doc_root[domain] = DOC_ROOT_BASE + str(counter)
            counter += 1

        add_document_root_to_vhost(path, domain_doc_root[domain])
        add_domain_to_document_root(domain, domain_doc_root[domain])


def swap_config(apache_root):
    shutil.rmtree(CONFIG.SERVER_ROOT)
    shutil.copytree(apache_root, SERVER_ROOT)
