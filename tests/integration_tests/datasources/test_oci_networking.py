import re
from typing import Iterator, Set

import pytest
import yaml

from tests.integration_tests.clouds import IntegrationCloud
from tests.integration_tests.instances import IntegrationInstance
from tests.integration_tests.integration_settings import PLATFORM
from tests.integration_tests.util import verify_clean_log

DS_CFG = """\
datasource:
  Oracle:
    configure_secondary_nics: {configure_secondary_nics}
"""


def customize_environment(
    client: IntegrationInstance,
    tmpdir,
    configure_secondary_nics: bool = False,
):
    cfg = tmpdir.join("01_oracle_datasource.cfg")
    with open(cfg, "w") as f:
        f.write(
            DS_CFG.format(configure_secondary_nics=configure_secondary_nics)
        )
    client.push_file(cfg, "/etc/cloud/cloud.cfg.d/01_oracle_datasource.cfg")

    client.execute("cloud-init clean --logs")
    client.restart()


def extract_interface_names(network_config: dict) -> Set[str]:
    if network_config["version"] == 1:
        interfaces = map(lambda conf: conf["name"], network_config["config"])
    elif network_config["version"] == 2:
        interfaces = network_config["ethernets"].keys()
    else:
        raise NotImplementedError(
            f'Implement me for version={network_config["version"]}'
        )
    return set(interfaces)


@pytest.mark.skipif(PLATFORM != "oci", reason="Test is OCI specific")
def test_oci_networking_iscsi_instance(client: IntegrationInstance, tmpdir):
    customize_environment(client, tmpdir, configure_secondary_nics=False)
    result_net_files = client.execute("ls /run/net-*.conf")
    assert result_net_files.ok, "No net files found under /run"

    log = client.read_from_file("/var/log/cloud-init.log")
    verify_clean_log(log)

    assert (
        "opc/v2/vnics/" not in log
    ), "vnic data was fetched and it should not have been"

    netplan_yaml = client.read_from_file("/etc/netplan/50-cloud-init.yaml")
    netplan_cfg = yaml.safe_load(netplan_yaml)
    configured_interfaces = extract_interface_names(netplan_cfg["network"])
    assert 1 <= len(
        configured_interfaces
    ), "Expected at least 1 primary network configuration."

    expected_interfaces = set(
        re.findall(r"/run/net-(.+)\.conf", result_net_files.stdout)
    )
    for expected_interface in expected_interfaces:
        assert (
            f"Reading from /run/net-{expected_interface}.conf" in log
        ), "Expected {expected_interface} not found in: {log}"

    not_found_interfaces = expected_interfaces.difference(
        configured_interfaces
    )
    assert not not_found_interfaces, (
        f"Interfaces, {not_found_interfaces}, expected to be configured in"
        f" {netplan_cfg['network']}"
    )
    assert client.execute("ping -c 2 canonical.com").ok


@pytest.fixture(scope="function")
def client_with_secondary_vnic(
    session_cloud: IntegrationCloud,
) -> Iterator[IntegrationInstance]:
    """Create an instance client and attach a temporary vnic"""
    with session_cloud.launch() as client:
        ip_address = client.instance.add_network_interface()
        yield client
        client.instance.remove_network_interface(ip_address)


@pytest.mark.skipif(PLATFORM != "oci", reason="Test is OCI specific")
def test_oci_networking_iscsi_instance_secondary_vnics(
    client_with_secondary_vnic: IntegrationInstance, tmpdir
):
    client = client_with_secondary_vnic
    customize_environment(client, tmpdir, configure_secondary_nics=True)

    log = client.read_from_file("/var/log/cloud-init.log")
    verify_clean_log(log)

    assert "opc/v2/vnics/" in log, f"vnics data not fetched in {log}"
    netplan_yaml = client.read_from_file("/etc/netplan/50-cloud-init.yaml")
    netplan_cfg = yaml.safe_load(netplan_yaml)
    configured_interfaces = extract_interface_names(netplan_cfg["network"])
    assert 2 <= len(
        configured_interfaces
    ), "Expected at least 1 primary and 1 secondary network configurations"

    result_net_files = client.execute("ls /run/net-*.conf")
    expected_interfaces = set(
        re.findall(r"/run/net-(.+)\.conf", result_net_files.stdout)
    )
    assert len(expected_interfaces) + 1 == len(configured_interfaces)
    assert client.execute("ping -c 2 canonical.com").ok


SYSTEM_CFG = """\
network:
  ethernets:
    id0:
      dhcp4: true
      dhcp6: true
      match:
        name: "ens*"
  version: 2
"""


def customize_netcfg(
    client: IntegrationInstance,
    tmpdir,
):
    cfg = tmpdir.join("net.cfg")
    with open(cfg, "w") as f:
        f.write(SYSTEM_CFG)
    client.push_file(cfg, "/etc/cloud/cloud.cfg.d/50-network-test.cfg")
    client.execute("cloud-init clean --logs")
    client.restart()


@pytest.mark.skipif(PLATFORM != "oci", reason="Test is OCI specific")
def test_oci_networking_system_cfg(client: IntegrationInstance, tmpdir):
    customize_netcfg(client, tmpdir)
    log = client.read_from_file("/var/log/cloud-init.log")
    verify_clean_log(log)

    assert (
        "Applying network configuration from system_cfg" in log
    ), "network source used wasn't system_cfg"
    netplan_yaml = client.read_from_file("/etc/netplan/50-cloud-init.yaml")
    netplan_cfg = yaml.safe_load(netplan_yaml)
    expected_netplan_cfg = yaml.safe_load(SYSTEM_CFG)
    assert expected_netplan_cfg == netplan_cfg



def _test_crawl(client, ip):
    assert client.execute("cloud-init clean --logs").ok
    assert client.execute("cloud-init init --local").ok
    log = client.read_from_file("/var/log/cloud-init.log")
    assert re.findall(f"Using metadata source:.*{ip}.*'", log)
    result = re.findall(r"Crawl of metadata service.* (\d+.\d+) seconds", log)
    if len(result) != 1:
        pytest.fail(f"Expected 1 metadata crawl time, got {result}")
    # 20 would still be a crazy long time for metadata service to crawl,
    # but it's short enough to know we're not waiting for a response
    assert float(result[0]) < 20

ORACLE_IPV4_IMDS_IP = "169.254.169.254"
ORACLE_IPV6_IMDS_IP = "http://[fe80::00c1:a9fe:a9fe%ens3]"

@pytest.mark.skipif(PLATFORM != "oci", reason="test is OCI specific")
def test_dual_stack(client: IntegrationInstance):
    # Drop IPv4 responses
    assert client.execute(f"iptables -I INPUT -s {ORACLE_IPV4_IMDS_IP} -j DROP").ok
    _test_crawl(client, f"http://[{ORACLE_IPV6_IMDS_IP}]")

    # Block IPv4 requests
    assert client.execute(f"iptables -I OUTPUT -d {ORACLE_IPV4_IMDS_IP} -j REJECT").ok
    _test_crawl(client, f"http://[{ORACLE_IPV6_IMDS_IP}]")

    # Re-enable IPv4
    assert client.execute(f"iptables -D OUTPUT -d {ORACLE_IPV4_IMDS_IP} -j REJECT").ok
    assert client.execute(f"iptables -D INPUT -s {ORACLE_IPV4_IMDS_IP} -j DROP").ok

    # Drop IPv6 responses
    assert client.execute(f"ip6tables -I INPUT -s {ORACLE_IPV6_IMDS_IP} -j DROP").ok
    _test_crawl(client, f"http://{ORACLE_IPV4_IMDS_IP}")

    # Block IPv6 requests
    assert client.execute(f"ip6tables -I OUTPUT -d {ORACLE_IPV6_IMDS_IP} -j REJECT").ok
    _test_crawl(client, f"http://{ORACLE_IPV4_IMDS_IP}")

    # Force NoDHCPLeaseError (by removing dhcp clients) and assert ipv6 still
    # works
    # Destructive test goes last
    # dhclient is at /sbin/dhclient on bionic but /usr/sbin/dhclient elseware
    for dhcp_client in ("dhclient", "dhcpcd"):
        if client.execute(f"command -v {dhcp_client}").ok:
            assert client.execute(f"rm $(command -v {dhcp_client})").ok

    client.restart()
    log = client.read_from_file("/var/log/cloud-init.log")
    assert "Crawl of metadata service using link-local ipv6 took" in log



@pytest.mark.skipif(PLATFORM != "oci", reason="test is OCI specific")
def test_single_stack(client: IntegrationInstance):
    # Drop IPv4 responses
    assert client.execute(f"iptables -I INPUT -s {ORACLE_IPV4_IMDS_IP} -j DROP").ok
    _test_crawl(client, f"http://[{ORACLE_IPV6_IMDS_IP}]")

    # Block IPv4 requests
    assert client.execute(f"iptables -I OUTPUT -d {ORACLE_IPV4_IMDS_IP} -j REJECT").ok
    _test_crawl(client, f"http://[{ORACLE_IPV6_IMDS_IP}]")

    # Force NoDHCPLeaseError (by removing dhcp clients) and assert ipv6 still
    # works
    # Destructive test goes last
    # dhclient is at /sbin/dhclient on bionic but /usr/sbin/dhclient elseware
    for dhcp_client in ("dhclient", "dhcpcd"):
        if client.execute(f"command -v {dhcp_client}").ok:
            assert client.execute(f"rm $(command -v {dhcp_client})").ok

    client.restart()
    log = client.read_from_file("/var/log/cloud-init.log")
    assert "Crawl of metadata service using link-local ipv6 took" in log
