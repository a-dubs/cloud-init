# This file is part of cloud-init. See LICENSE file for license information.

"""Module for ephemeral network context managers
"""
import contextlib
import logging
from functools import partial
from typing import Any, Callable, Dict, List, Optional

import cloudinit.net as net
import cloudinit.netinfo as netinfo
from cloudinit.net.dhcp import NoDHCPLeaseError, maybe_perform_dhcp_discovery
from cloudinit.subp import ProcessExecutionError

LOG = logging.getLogger(__name__)


class EphemeralIPv4Network:
    """Context manager which sets up temporary static network configuration.

    No operations are performed if the provided interface already has the
    specified configuration.
    This can be verified with the connectivity_url_data.
    If unconnected, bring up the interface with valid ip, prefix and broadcast.
    If router is provided setup a default route for that interface. Upon
    context exit, clean up the interface leaving no configuration behind.
    """

    def __init__(
        self,
        distro,
        interface,
        ip,
        prefix_or_mask,
        broadcast,
        interface_addrs_before_dhcp: dict,
        router=None,
        static_routes=None,
    ):
        """Setup context manager and validate call signature.

        @param interface: Name of the network interface to bring up.
        @param ip: IP address to assign to the interface.
        @param prefix_or_mask: Either netmask of the format X.X.X.X or an int
            prefix.
        @param broadcast: Broadcast address for the IPv4 network.
        @param router: Optionally the default gateway IP.
        @param static_routes: Optionally a list of static routes from DHCP
        """
        if not all([interface, ip, prefix_or_mask, broadcast]):
            raise ValueError(
                "Cannot init network on {0} with {1}/{2} and bcast {3}".format(
                    interface, ip, prefix_or_mask, broadcast
                )
            )
        try:
            self.prefix = net.ipv4_mask_to_net_prefix(prefix_or_mask)
        except ValueError as e:
            raise ValueError(
                "Cannot setup network, invalid prefix or "
                "netmask: {0}".format(e)
            ) from e

        self.interface = interface
        self.ip = ip
        self.broadcast = broadcast
        self.router = router
        self.static_routes = static_routes
        # List of commands to run to cleanup state.
        self.cleanup_cmds: List[Callable] = []
        self.distro = distro
        self.cidr = f"{self.ip}/{self.prefix}"
        self.interface_addrs_before_dhcp = interface_addrs_before_dhcp.get(
            self.interface, {}
        )

    def __enter__(self):
        """Set up ephemeral network if interface is not connected.

        This context manager handles the lifecycle of the network interface,
        addresses, routes, etc
        """

        try:
            try:
                self._bringup_device()
            except ProcessExecutionError as e:
                if "File exists" not in str(
                    e.stderr
                ) and "Address already assigned" not in str(e.stderr):
                    raise

            # rfc3442 requires us to ignore the router config *if*
            # classless static routes are provided.
            #
            # https://tools.ietf.org/html/rfc3442
            #
            # If the DHCP server returns both a Classless Static Routes
            # option and a Router option, the DHCP client MUST ignore
            # the Router option.
            #
            # Similarly, if the DHCP server returns both a Classless
            # Static Routes option and a Static Routes option, the DHCP
            # client MUST ignore the Static Routes option.
            if self.static_routes:
                self._bringup_static_routes()
            elif self.router:
                self._bringup_router()
        except ProcessExecutionError:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, excp_type, excp_value, excp_traceback):
        """Teardown anything we set up."""
        for cmd in self.cleanup_cmds:
            cmd()

    def _bringup_device(self):
        """Perform the ip commands to fully set up the device.

        Dhcp clients behave differently in how they leave link state and ip
        address assignment.

        Attempt assigning address and setting up link if needed to be done.
        Set cleanup_cmds to return the interface state to how it was prior
        to execution of the dhcp client.
        """
        LOG.debug(
            "Attempting setup of ephemeral network on %s with %s brd %s",
            self.interface,
            self.cidr,
            self.broadcast,
        )
        interface_addrs_after_dhcp = netinfo.netdev_info().get(
            self.interface, {}
        )
        has_link = interface_addrs_after_dhcp.get("up")
        had_link = self.interface_addrs_before_dhcp.get("up")
        has_ip = self.ip in [
            ip.get("ip") for ip in interface_addrs_after_dhcp.get("ipv4", {})
        ]
        had_ip = self.ip in [
            ip.get("ip")
            for ip in self.interface_addrs_before_dhcp.get("ipv4", {})
        ]

        if has_ip:
            LOG.debug(
                "Skip adding ip address: %s already has address %s",
                self.interface,
                self.ip,
            )
        else:
            self.distro.net_ops.add_addr(
                self.interface, self.cidr, self.broadcast
            )
        if has_link:
            LOG.debug(
                "Skip bringing up network link: interface %s is already up",
                self.interface,
            )
        else:
            self.distro.net_ops.link_up(self.interface, family="inet")
        if had_link:
            LOG.debug(
                "Not queueing link down: link [%s] was up prior before "
                "receiving a dhcp lease",
                self.interface,
            )
        else:
            self.cleanup_cmds.append(
                partial(
                    self.distro.net_ops.link_down,
                    self.interface,
                    family="inet",
                )
            )
        if had_ip:
            LOG.debug(
                "Not queueing address removal: address %s was assigned before "
                "receiving a dhcp lease",
                self.ip,
            )
        else:
            self.cleanup_cmds.append(
                partial(
                    self.distro.net_ops.del_addr, self.interface, self.cidr
                )
            )

    def _bringup_static_routes(self):
        # static_routes = [("169.254.169.254/32", "130.56.248.255"),
        #                  ("0.0.0.0/0", "130.56.240.1")]
        for net_address, gateway in self.static_routes:
            # Use "append" rather than "add" since the DHCP server may provide
            # rfc3442 classless static routes with multiple routes to the same
            # subnet via different routers or local interface addresses.
            #
            # In this scenario, `ip r add` fails.
            #
            # RHBZ: #2003231
            self.distro.net_ops.append_route(
                self.interface, net_address, gateway
            )
            self.cleanup_cmds.insert(
                0,
                partial(
                    self.distro.net_ops.del_route,
                    self.interface,
                    net_address,
                    gateway=gateway,
                ),
            )

    def _bringup_router(self):
        """Perform the ip commands to fully setup the router if needed."""
        # Check if a default route exists and exit if it does
        out = self.distro.net_ops.get_default_route()
        if "default" in out:
            LOG.debug(
                "Skip ephemeral route setup. %s already has default route: %s",
                self.interface,
                out.strip(),
            )
            return
        self.distro.net_ops.add_route(
            self.interface, self.router, source_address=self.ip
        )
        self.cleanup_cmds.insert(
            0,
            partial(
                self.distro.net_ops.del_route,
                self.interface,
                self.router,
                source_address=self.ip,
            ),
        )
        self.distro.net_ops.add_route(
            self.interface, "default", gateway=self.router
        )
        self.cleanup_cmds.insert(
            0,
            partial(self.distro.net_ops.del_route, self.interface, "default"),
        )


class EphemeralIPv6Network:
    """Context manager which sets up a ipv6 link local address

    The linux kernel assigns link local addresses on link-up, which is
    sufficient for link-local communication.
    """

    def __init__(self, distro, interface):
        """Setup context manager and validate call signature.

        @param interface: Name of the network interface to bring up.
        @param ip: IP address to assign to the interface.
        @param prefix: IPv6 uses prefixes, not netmasks
        """
        if not interface:
            raise ValueError("Cannot init network on {0}".format(interface))

        self.interface = interface
        self.distro = distro

    def __enter__(self):
        """linux kernel does autoconfiguration even when autoconf=0

        https://www.kernel.org/doc/html/latest/networking/ipv6.html
        """
        if net.read_sys_net(self.interface, "operstate") != "up":
            self.distro.net_ops.link_up(self.interface)

    def __exit__(self, *_args):
        """No need to set the link to down state"""


class EphemeralDHCPv4:
    def __init__(
        self,
        distro,
        iface=None,
        #TODO: combine these. keeping connectivity_url_data for backwards compatibility
        connectivity_url_data: Optional[Dict[str, Any]] = None,
        connectivity_urls: Optional[List[Dict[str, Any]]] = None,
        dhcp_log_func=None,
    ):
        self.iface = iface
        self._ephipv4: Optional[EphemeralIPv4Network] = None
        self.lease: Optional[Dict[str, Any]] = None
        self.dhcp_log_func = dhcp_log_func
        self.connectivity_url_data = connectivity_url_data
        self.connectivity_urls = connectivity_urls
        self.distro = distro
        self.interface_addrs_before_dhcp = netinfo.netdev_info()

    def __enter__(self):
        """Setup sandboxed dhcp context, unless connectivity_url can already be
        reached."""
        # combine the connectivity_url_data and connectivity_urls into a single list
        urls_data = self.connectivity_urls or []
        if self.connectivity_url_data:
            urls_data.append(self.connectivity_url_data)
        for url_data in urls_data:
            if net.has_url_connectivity(url_data):
                LOG.debug(
                    "Skip ephemeral DHCP setup, instance has connectivity"
                    " to %s",
                    url_data,
                )
                return
        return self.obtain_lease()

    def __exit__(self, excp_type, excp_value, excp_traceback):
        """Teardown sandboxed dhcp context."""
        self.clean_network()

    def clean_network(self):
        """Exit _ephipv4 context to teardown of ip configuration performed."""
        self.lease = None
        if self._ephipv4:
            self._ephipv4.__exit__(None, None, None)

    def obtain_lease(self):
        """Perform dhcp discovery in a sandboxed environment if possible.

        @return: A dict representing dhcp options on the most recent lease
            obtained from the dhclient discovery if run, otherwise an error
            is raised.

        @raises: NoDHCPLeaseError if no leases could be obtained.
        """
        if self.lease:
            return self.lease
        self.lease = maybe_perform_dhcp_discovery(
            self.distro, self.iface, self.dhcp_log_func
        )
        if not self.lease:
            raise NoDHCPLeaseError()
        LOG.debug(
            "Received dhcp lease on %s for %s/%s",
            self.lease["interface"],
            self.lease["fixed-address"],
            self.lease["subnet-mask"],
        )
        nmap = {
            "interface": "interface",
            "ip": "fixed-address",
            "prefix_or_mask": "subnet-mask",
            "broadcast": "broadcast-address",
            "static_routes": [
                "rfc3442-classless-static-routes",
                "classless-static-routes",
                "static_routes",
                "unknown-121",
            ],
            "router": "routers",
        }
        kwargs = self.extract_dhcp_options_mapping(nmap)
        if not kwargs["broadcast"]:
            kwargs["broadcast"] = net.mask_and_ipv4_to_bcast_addr(
                kwargs["prefix_or_mask"], kwargs["ip"]
            )
        if kwargs["static_routes"]:
            kwargs["static_routes"] = (
                self.distro.dhcp_client.parse_static_routes(
                    kwargs["static_routes"]
                )
            )
        ephipv4 = EphemeralIPv4Network(
            self.distro,
            interface_addrs_before_dhcp=self.interface_addrs_before_dhcp,
            **kwargs,
        )
        ephipv4.__enter__()
        self._ephipv4 = ephipv4
        return self.lease

    def extract_dhcp_options_mapping(self, nmap):
        result = {}
        for internal_reference, lease_option_names in nmap.items():
            if isinstance(lease_option_names, list):
                self.get_first_option_value(
                    internal_reference, lease_option_names, result
                )
            else:
                result[internal_reference] = self.lease.get(lease_option_names)
        return result

    def get_first_option_value(
        self, internal_mapping, lease_option_names, result
    ):
        for different_names in lease_option_names:
            if not result.get(internal_mapping):
                result[internal_mapping] = self.lease.get(different_names)


class EphemeralIPNetwork:
    """Combined ephemeral context manager for IPv4 and IPv6

    Either ipv4 or ipv6 ephemeral network may fail to initialize, but if either
    succeeds, then this context manager will not raise exception. This allows
    either ipv4 or ipv6 ephemeral network to succeed, but requires that error
    handling for networks unavailable be done within the context.
    """

    def __init__(
        self,
        distro,
        interface,
        ipv6: bool = False,
        ipv4: bool = True,
        connectivity_url_data: Optional[Dict[str, Any]] = None,
        ipv6_imds_endpoint_url_data: Optional[Dict[str, Any]] = None,
        prefer_ipv6: bool = False,
    ):
        self.interface = interface
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.stack = contextlib.ExitStack()
        self.state_msg: str = ""
        self.distro = distro
        self.connectivity_url_data = connectivity_url_data
        self.ipv6_imds_endpoint_url_data = ipv6_imds_endpoint_url_data
        self.prefer_ipv6 = prefer_ipv6

        # will be updated by the context manager
        self.ipv6_reachable = False

    def __enter__(self):
        if not (self.ipv4 or self.ipv6):
            # no ephemeral network requested, but this object still needs to
            # function as a context manager
            return self
        exceptions = []
        ephemeral_obtained = False
        
        if self.prefer_ipv6:
            LOG.debug("[CPC-3194] Attempting to bring up ipv6 ephemeral network first")
            ephemeral_obtained, exceptions = self._do_ipv6(ephemeral_obtained, exceptions)
            LOG.debug("[CPC-3194] ipv6 ephemeral network setup result: %s", ephemeral_obtained)
            ipv6_imds_reachable = self._check_ipv6_connectivity()
            self.ipv6_reachable = ipv6_imds_reachable
            LOG.debug("[CPC-3194] ipv6 connectivity check result: %s", ipv6_imds_reachable)
            if not ephemeral_obtained and self.ipv4 and not ipv6_imds_reachable:
                LOG.debug("[CPC-3194] Attempting to bring up ipv4 ephemeral network since ipv6 failed")
                ephemeral_obtained, exceptions = self._do_ipv4(ephemeral_obtained, exceptions)
        else:
            ephemeral_obtained, exceptions = self._do_ipv4(ephemeral_obtained, exceptions)
            if not ephemeral_obtained and self.ipv6:
                ephemeral_obtained, exceptions = self._do_ipv6(ephemeral_obtained, exceptions)

        if not ephemeral_obtained:
            # Ephemeral network setup failed in linkup for both ipv4 and
            # ipv6. Raise only the first exception found.
            LOG.error(
                "Failed to bring up EphemeralIPNetwork. "
                "Datasource setup cannot continue"
            )
            raise exceptions[0]
        return self

    def _do_ipv4(self, ephemeral_obtained, exceptions) -> tuple[str, list[Exception]]:
        try:
            self.stack.enter_context(
                EphemeralDHCPv4(
                    distro=self.distro,
                    iface=self.interface,
                    connectivity_url_data=self.connectivity_url_data,
                )
            )
            ephemeral_obtained = True
            LOG.info("[CPC-3194] Successfully brought up %s for ipv4.", self)
        except (ProcessExecutionError, NoDHCPLeaseError) as e:
            LOG.info("[CPC-3194] Failed to bring up %s for ipv4.", self)
            exceptions.append(e)
        return ephemeral_obtained, exceptions
    
    def _do_ipv6(self, ephemeral_obtained, exceptions) -> tuple[str, list[Exception]]:
        try:
            self.stack.enter_context(
                EphemeralIPv6Network(
                    self.distro,
                    self.interface,
                )
            )
            ephemeral_obtained = True
            LOG.info("[CPC-3194] Successfully brought up %s for ipv6.", self)
        except ProcessExecutionError as e:
            LOG.info("[CPC-3194] Failed to bring up %s for ipv6.", self)
            # we don't set ephemeral_obtained to False here because we want to
            # retain a potential true value from any previous successful
            # ephemeral network setup
            exceptions.append(e)
        return ephemeral_obtained, exceptions
    
    def _check_ipv6_connectivity(self):
        if self.ipv6_imds_endpoint_url_data:
            LOG.debug("[CPC-3194] Checking ipv6 connectivity for %s", 
                      self.ipv6_imds_endpoint_url_data)
            url_response = net.readurl(
                check_status=False,
                url=self.ipv6_imds_endpoint_url_data["url"],
                headers=self.ipv6_imds_endpoint_url_data.get("headers"),
                timeout=self.ipv6_imds_endpoint_url_data.get("timeout", 0.5),
            )
            LOG.debug(
                "[CPC-3194] Response from ipv6 connectivity check: %s",
                url_response.code,
            ) 
            # check if the response is ok
            if url_response.code < 400:
                LOG.debug("[CPC-3194] Successfully checked ipv6 connectivity.")
                return True
        else:
            LOG.debug("[CPC-3194] No IPv6 connectivity URL data provided. "
                      "Assuming IPv6 connectivity is not available.")
        return False

    def __exit__(self, *_args):
        self.stack.close()
