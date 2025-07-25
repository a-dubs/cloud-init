# This file is part of cloud-init. See LICENSE file for license information.

from tests.unittests.helpers import CiTestCase, get_distro, mock
from tests.unittests.util import MockDistro


class TestManageService(CiTestCase):

    with_logs = True

    def setUp(self):
        super(TestManageService, self).setUp()
        self.dist = MockDistro()

    @mock.patch.object(MockDistro, "uses_systemd", return_value=True)
    @mock.patch("cloudinit.distros.subp.subp")
    def test_manage_service_systemctl_initcmd(self, m_subp, m_sysd):
        self.dist.init_cmd = ["systemctl"]
        self.dist.manage_service("start", "myssh")
        m_subp.assert_called_with(
            ["systemctl", "start", "myssh"], capture=True, rcs=None
        )

    @mock.patch.object(MockDistro, "uses_systemd", return_value=False)
    @mock.patch("cloudinit.distros.subp.subp")
    def test_manage_service_service_initcmd(self, m_subp, m_sysd):
        self.dist.init_cmd = ["service"]
        self.dist.manage_service("start", "myssh")
        m_subp.assert_called_with(
            ["service", "myssh", "start"], capture=True, rcs=None
        )

    @mock.patch.object(MockDistro, "uses_systemd", return_value=False)
    @mock.patch("cloudinit.distros.subp.subp")
    def test_manage_service_rcservice_initcmd(self, m_subp, m_sysd):
        dist = get_distro("alpine")
        dist.init_cmd = ["rc-service", "--nocolor"]
        dist.manage_service("start", "myssh")
        m_subp.assert_called_with(
            ["rc-service", "--nocolor", "myssh", "start"],
            capture=True,
            rcs=None,
        )

    @mock.patch("cloudinit.distros.subp.subp")
    def test_manage_service_alpine_rcupdate_cmd(self, m_subp):
        dist = get_distro("alpine")
        dist.update_cmd = ["rc-update", "--nocolor"]
        dist.manage_service("enable", "myssh")
        m_subp.assert_called_with(
            ["rc-update", "--nocolor", "add", "myssh"], capture=True, rcs=None
        )

    @mock.patch("cloudinit.distros.subp.subp")
    def test_manage_service_rcctl_initcmd(self, m_subp):
        dist = get_distro("openbsd")
        dist.init_cmd = ["rcctl"]
        dist.manage_service("start", "myssh")
        m_subp.assert_called_with(
            ["rcctl", "start", "myssh"], capture=True, rcs=None
        )

    @mock.patch("cloudinit.distros.subp.subp")
    def test_manage_service_fbsd_service_initcmd(self, m_subp):
        dist = get_distro("freebsd")
        dist.init_cmd = ["service"]
        dist.manage_service("enable", "myssh")
        m_subp.assert_called_with(
            ["service", "myssh", "enable"], capture=True, rcs=None
        )

    @mock.patch.object(MockDistro, "uses_systemd", return_value=True)
    @mock.patch("cloudinit.distros.subp.subp")
    def test_manage_service_systemctl(self, m_subp, m_sysd):
        self.dist.init_cmd = ["ignore"]
        self.dist.manage_service("start", "myssh")
        m_subp.assert_called_with(
            ["systemctl", "start", "myssh"], capture=True, rcs=None
        )

    @mock.patch.object(MockDistro, "uses_systemd", return_value=True)
    @mock.patch("cloudinit.distros.subp.subp")
    def test_manage_service_disable_systemctl(self, m_subp, m_sysd):
        self.dist.init_cmd = ["ignore"]
        self.dist.manage_service("disable", "myssh")
        m_subp.assert_called_with(
            ["systemctl", "disable", "myssh"], capture=True, rcs=None
        )
