"""WireGuard over systemd-networkd DynDNS watchdog daemon."""

from __future__ import annotations
from argparse import ArgumentParser, Namespace
from configparser import ConfigParser
from json import dump, load
from logging import DEBUG, INFO, basicConfig, getLogger
from os import linesep
from pathlib import Path
from socket import gaierror, gethostbyname
from subprocess import DEVNULL, CalledProcessError, check_call
from typing import Generator, NamedTuple


__all__ = [
    "CACHE",
    "NotAWireGuardDevice",
    "NotAWireGuardClient",
    "get_networks",
    "main",
    "Cache",
    "WireGuardClient",
]


CACHE = Path("/var/cache/dynwg.json")
SYSTEMD_NETWORK = Path("/etc/systemd/network")
PING = "/usr/bin/ping"
WG = "/usr/bin/wg"
LOGGER = getLogger(__file__)
LOG_FORMAT = "[%(levelname)s] %(name)s: %(message)s"


class NotAWireGuardDevice(Exception):
    """Indicates that the respective device is not a WireGuard device."""


class NotAWireGuardClient(Exception):
    """Indicates that the device is not a WireGuard client configuration."""


def get_networks(interface: str) -> Generator[ConfigParser, None, None]:
    """Returns the network configuration for the respective interface."""

    for path in SYSTEMD_NETWORK.glob("*.network"):
        network = ConfigParser(strict=False)

        if not network.read(path):
            LOGGER.warning("Could not read *.network file: %s", path)
            continue

        try:
            if network["Match"]["Name"] == interface:
                yield network
        except KeyError:
            LOGGER.warning("Network has no Name: %s", path)


def get_args() -> Namespace:
    """Returns the command line arguments."""

    parser = ArgumentParser(description="WireGuard DynDNS watchdog.")
    parser.add_argument(
        "-c",
        "--check-gateway",
        action="store_true",
        help="also check whether gateway is reachable",
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", help="enable debug logging"
    )
    return parser.parse_args()


def main():
    """Daemon's main loop."""

    args = get_args()
    basicConfig(level=DEBUG if args.debug else INFO, format=LOG_FORMAT)

    with Cache(CACHE) as cache:
        for wire_guard_client in WireGuardClient.all():
            LOGGER.info("Checking: %s.", wire_guard_client.interface)
            wire_guard_client.check(cache, check_gateway=args.check_gateway)


class Cache(dict):
    """Host name → IP address cache."""

    def __new__(cls, _):
        return super().__new__(cls)

    def __init__(self, path: Path):
        super().__init__()
        self.path = path
        self.synced = True

    def __setitem__(self, key, value):
        self.synced = self.synced and self.get(key) == value
        return super().__setitem__(key, value)

    def __enter__(self):
        self.load()
        return self

    def __exit__(self, *_):
        self.dump()

    def ip_changed(self, hostname: str) -> bool:
        """Determines whether the IP address
        of the specified host has changed.
        """
        cached_ip = self.get(hostname)

        try:
            self[hostname] = current_ip = gethostbyname(hostname)
        except gaierror:
            LOGGER.error('Cannot resolve hostname: "%s".', hostname)
            return True

        if cached_ip is None:
            LOGGER.info('Added host "%s": %s', hostname, current_ip)
            return True

        if cached_ip == current_ip:
            return False

        LOGGER.info('Host "%s": %s → %s', hostname, cached_ip, current_ip)
        return True

    def load(self):
        """Loads the cache."""
        try:
            with self.path.open("r") as file:
                self.update(load(file))
        except FileNotFoundError:
            self.synced = False  # Ensure initial file creation.

    def dump(self, force: bool = False):
        """Dumps the cache."""
        if not self.synced or force:
            with self.path.open("w") as file:
                dump(self, file, indent=2)
                file.write(linesep)

            self.synced = True


class WireGuardClient(NamedTuple):
    """Relevant WireGuard configuration settings."""

    interface: str
    pubkey: str
    endpoint: str
    gateway: str

    @classmethod
    def from_netdev(cls, netdev: ConfigParser) -> WireGuardClient:
        """Creates a config tuple from the respective netdev data."""
        if netdev["NetDev"]["Kind"] != "wireguard":
            raise NotAWireGuardDevice()

        try:
            endpoint = netdev["WireGuardPeer"]["Endpoint"]
            pubkey = netdev["WireGuardPeer"]["PublicKey"]
        except KeyError:
            raise NotAWireGuardClient() from None

        interface = netdev["NetDev"]["Name"]
        gateway = None

        for network in get_networks(interface):
            try:
                gateway = network["Route"]["Gateway"]
            except KeyError:
                continue

            break  # Use first available gateway.

        return cls(interface, pubkey, endpoint, gateway)

    @classmethod
    def all(cls) -> Generator[WireGuardClient, None, None]:
        """Yields all available configurations."""
        for path in SYSTEMD_NETWORK.glob("*.netdev"):
            netdev = ConfigParser(strict=False)

            if not netdev.read(path):
                LOGGER.warning("Could not read *.netdev file: %s", path)
                continue

            try:
                yield cls.from_netdev(netdev)
            except KeyError:
                LOGGER.warning("Invalid netdev configuration: %s", path)
            except NotAWireGuardDevice:
                LOGGER.debug("Not a WireGuard device: %s", path)
            except NotAWireGuardClient:
                LOGGER.debug("Not a WireGuard client: %s", path)

    @property
    def hostname(self) -> str:
        """Returns the hostname."""
        return self.endpoint.split(":", maxsplit=1)[0]

    @property
    def gateway_unreachable(self) -> bool:
        """Pings the gateway to check if it is (un)reachable."""
        if self.gateway is None:
            LOGGER.error("No gateway specified, cannot ping.")
            LOGGER.info("Assuming not reachable.")
            return True

        command = (PING, "-c", "3", "-W", "3", self.gateway)

        try:
            check_call(command, stdout=DEVNULL, stderr=DEVNULL)
        except CalledProcessError:
            LOGGER.info('Gateway "%s" is not reachable.', self.gateway)
            return True

        return False

    @property
    def reset_command(self) -> tuple:
        """Returns the command tuple to reset the WireGuard interface."""
        return (
            WG,
            "set",
            self.interface,
            "peer",
            self.pubkey,
            "endpoint",
            self.endpoint,
        )

    def reset(self) -> bool:
        """Resets the interface."""
        try:
            check_call(self.reset_command)
        except CalledProcessError as cpe:
            LOGGER.error("Resetting of interface failed.")
            LOGGER.debug(cpe)
            return False

        LOGGER.info("Interface reset.")
        return True

    def check(self, cache: Cache, check_gateway: bool = False) -> bool:
        """Checks, whether the WireGuard connection is still intact."""
        if cache.ip_changed(self.hostname):
            return self.reset()

        if check_gateway and self.gateway_unreachable:
            return self.reset()

        return True
