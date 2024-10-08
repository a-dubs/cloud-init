# This file is part of cloud-init. See LICENSE file for license information.
from unittest import mock

import pytest

from cloudinit import util
from tests.unittests.util import get_cloud

LOCALE_PATH = "/etc/default/locale"


@pytest.mark.usefixtures("fake_filesystem")
class TestDebianApplyLocale:
    @pytest.fixture
    def m_subp(self, mocker):
        mocker.patch(
            "cloudinit.distros.debian.subp.which",
            return_value="/usr/bin/locale-gen",
        )
        yield mocker.patch(
            "cloudinit.distros.debian.subp.subp", return_value=(None, None)
        )

    @pytest.fixture
    def distro(self):
        yield get_cloud(distro="debian").distro

    def test_no_rerun(self, distro, m_subp):
        """If system has defined locale, no re-run is expected."""
        locale = "en_US.UTF-8"
        util.write_file(LOCALE_PATH, "LANG=%s\n" % locale, omode="w")
        distro.apply_locale(locale, out_fn=LOCALE_PATH)
        m_subp.assert_not_called()

    @pytest.mark.parametrize(
        "which_response,install_pkgs",
        (("", ["locales"]), ("/usr/bin/update-locale", [])),
    )
    def test_no_regen_on_c_utf8(
        self, which_response, install_pkgs, distro, mocker, m_subp
    ):
        """If locale is set to C.UTF8, do not attempt to call locale-gen.

        Install locales deb package if not present and update-locale is called.
        """
        m_which = mocker.patch(
            "cloudinit.distros.debian.subp.which",
            return_value=which_response,
        )
        m_subp.return_value = (None, None)
        locale = "C.UTF-8"
        util.write_file(LOCALE_PATH, "LANG=%s\n" % "en_US.UTF-8", omode="w")
        with mock.patch.object(distro, "install_packages") as m_install:
            distro.apply_locale(locale, out_fn=LOCALE_PATH)
        assert [
            ["update-locale", f"--locale-file={LOCALE_PATH}", f"LANG={locale}"]
        ] == [p[0][0] for p in m_subp.call_args_list]
        m_which.assert_called_with("update-locale")
        if install_pkgs:
            m_install.assert_called_once_with(install_pkgs)
        else:
            m_install.assert_not_called()

    def test_rerun_if_different(self, distro, m_subp, caplog):
        """If system has different locale, locale-gen should be called."""
        locale = "en_US.UTF-8"
        util.write_file(LOCALE_PATH, "LANG=fr_FR.UTF-8", omode="w")
        distro.apply_locale(locale, out_fn=LOCALE_PATH)
        assert [
            ["locale-gen", locale],
            [
                "update-locale",
                f"--locale-file={LOCALE_PATH}",
                f"LANG={locale}",
            ],
        ] == [p[0][0] for p in m_subp.call_args_list]
        assert (
            "System locale set to fr_FR.UTF-8 via /etc/default/locale"
            in caplog.text
        )
        assert "Generating locales for en_US.UTF-8" in caplog.text
        assert (
            "Updating /etc/default/locale with locale setting LANG=en_US.UTF-8"
            in caplog.text
        )

    @pytest.mark.parametrize(
        "which_response,install_pkgs",
        (("", ["locales"]), ("/usr/bin/locale-gen", [])),
    )
    def test_rerun_if_no_file(
        self, which_response, install_pkgs, mocker, distro, m_subp
    ):
        """If system has no locale file, locale-gen should be called.

        Install locales package if absent and locale-gen called.
        """
        m_which = mocker.patch(
            "cloudinit.distros.debian.subp.which",
            return_value=which_response,
        )
        locale = "en_US.UTF-8"
        with mock.patch.object(distro, "install_packages") as m_install:
            distro.apply_locale(locale, out_fn=LOCALE_PATH)
        assert [
            ["locale-gen", locale],
            [
                "update-locale",
                f"--locale-file={LOCALE_PATH}",
                f"LANG={locale}",
            ],
        ] == [p[0][0] for p in m_subp.call_args_list]
        assert [
            mock.call("locale-gen"),
            mock.call("update-locale"),
        ] == m_which.call_args_list
        if install_pkgs:
            m_install.assert_called_with(install_pkgs)
        else:
            m_install.assert_not_called()

    def test_rerun_on_unset_system_locale(self, distro, m_subp, caplog):
        """If system has unset locale, locale-gen should be called."""
        locale = "en_US.UTF-8"
        util.write_file(LOCALE_PATH, "LANG=", omode="w")
        distro.apply_locale(locale, out_fn=LOCALE_PATH)
        assert [
            ["locale-gen", locale],
            [
                "update-locale",
                f"--locale-file={LOCALE_PATH}",
                f"LANG={locale}",
            ],
        ] == [p[0][0] for p in m_subp.call_args_list]
        assert (
            "System locale not found in /etc/default/locale. Assuming system "
            "locale is C.UTF-8 based on hardcoded default" in caplog.text
        )
        assert "Generating locales for en_US.UTF-8" in caplog.text
        assert (
            "Updating /etc/default/locale with locale setting LANG=en_US.UTF-8"
            in caplog.text
        )

    def test_rerun_on_mismatched_keys(self, distro, m_subp):
        """If key is LC_ALL and system has only LANG, rerun is expected."""
        locale = "en_US.UTF-8"
        util.write_file(LOCALE_PATH, "LANG=", omode="w")
        distro.apply_locale(locale, out_fn=LOCALE_PATH, keyname="LC_ALL")
        assert [
            ["locale-gen", locale],
            [
                "update-locale",
                f"--locale-file={LOCALE_PATH}",
                f"LC_ALL={locale}",
            ],
        ] == [p[0][0] for p in m_subp.call_args_list]

    def test_falseish_locale_raises_valueerror(self, distro, m_subp):
        """locale as None or "" is invalid and should raise ValueError."""

        with pytest.raises(
            ValueError, match="Failed to provide locale value."
        ):
            distro.apply_locale(None)
            m_subp.assert_not_called()

        with pytest.raises(
            ValueError, match="Failed to provide locale value."
        ):
            distro.apply_locale("")
            m_subp.assert_not_called()
