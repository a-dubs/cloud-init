# This file is part of cloud-init. See LICENSE file for license information.

from cloudinit import util
from tests.unittests.helpers import CiTestCase, get_distro


class TestArch(CiTestCase):
    def test_get_distro(self):
        distro = get_distro("arch")
        hostname = "myhostname"
        hostfile = self.tmp_path("hostfile")
        distro._write_hostname(hostname, hostfile)
        self.assertEqual(hostname + "\n", util.load_text_file(hostfile))
