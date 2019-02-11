#! /usr/bin/env python3
"""WireGuard over systemd-networkd DynDNS watchdog daemon."""

from configparser import ConfigParser
from contextlib import suppress
from json import dump, load
from pathlib import Path
from socket import gaierror, gethostbyname
from subprocess import DEVNULL, CalledProcessError, check_call
from sys import stderr
from typing import NamedTuple


CACHE = Path('/var/cache/dynwg.json')
SYSTEMD_NETWORK = Path('/etc/systemd/network')
NETDEVS = SYSTEMD_NETWORK.glob('*.netdev')
NETWORKS = SYSTEMD_NETWORK.glob('*.network')
PING = '/usr/bin/ping'
WG = '/usr/bin/wg'


class NotAWireGuardDevice(Exception):
    """Indicates that the respective device is not a WireGuard device."""


class NotAWireGuardClient(Exception):
    """Indicates that the device is not a WireGuard client configuration."""


def error(*msg):
    """Prints an error message."""

    print(*msg, file=stderr, flush=True)


def get_networks(interface):
    """Returns the network configuration for the respective interface."""

    for path in NETWORKS:
        network = ConfigParser(strict=False)
        network.read(path)

        try:
            if network['Match']['Name'] == interface:
                yield network
        except KeyError:
            continue


def main():
    """Daemon's main loop."""

    with Cache(CACHE) as cache:
        for wire_guard_client in WireGuardClient.all():
            print(f'Checking: {wire_guard_client.interface}.', flush=True)
            wire_guard_client.check(cache)


class Cache(dict):
    """Host name → IP address cache."""

    def __new__(cls, _):
        return super().__new__(cls)

    def __init__(self, path):
        super().__init__()
        self.path = path
        self._dirty = False

    def __setitem__(self, key, value):
        self.dirty = self.get(key) != value
        return super().__setitem__(key, value)

    def __enter__(self):
        self.load()
        return self

    def __exit__(self, *_):
        self.dump()

    @property
    def dirty(self):
        """Determines whether the cache is considered dirty."""
        return self._dirty

    @dirty.setter
    def dirty(self, dirty):
        """Sets whether the cache is dirty."""
        self._dirty = self._dirty or dirty

    def load(self):
        """Loads the cache."""
        try:
            with self.path.open('r') as file:
                self.update(load(file))
        except FileNotFoundError:
            self.dirty = True   # Ensure initial file creation.

    def dump(self, force=False):
        """Dumps the cache."""
        if self.dirty or force:
            with self.path.open('w') as file:
                dump(self, file, indent=2)


class WireGuardClient(NamedTuple):
    """Relevant WireGuard configuration settings."""

    interface: str
    pubkey: str
    endpoint: str
    gateway: str

    @classmethod
    def from_netdev(cls, netdev):
        """Creates a config tuple from the respective netdev data."""
        if netdev['NetDev']['Kind'] != 'wireguard':
            raise NotAWireGuardDevice()

        try:
            endpoint = netdev['WireGuardPeer']['Endpoint']
        except KeyError:
            raise NotAWireGuardClient()

        interface = netdev['NetDev']['Name']
        pubkey = netdev['WireGuardPeer']['PublicKey']
        gateway = None

        for network in get_networks(interface):
            try:
                gateway = network['Route']['Gateway']
            except KeyError:
                continue

        return cls(interface, pubkey, endpoint, gateway)

    @classmethod
    def all(cls):
        """Yields all available configurations."""
        for path in NETDEVS:
            netdev = ConfigParser(strict=False)
            netdev.read(path)

            with suppress(NotAWireGuardDevice, NotAWireGuardClient, KeyError):
                yield cls.from_netdev(netdev)

    @property
    def hostname(self):
        """Returns the hostname."""
        hostname, *_ = self.endpoint.split(':')     # Discard port.
        return hostname

    @property
    def current_ip(self):
        """Returns the host's current IP address."""
        return gethostbyname(self.hostname)

    def ip_changed(self, cache):
        """Determines whether the IP address
        of the specified host has changed.
        """
        cached_ip = cache.get(self.hostname)

        try:
            cache[self.hostname] = current_ip = self.current_ip
        except gaierror:
            error(f'Cannot resolve host: "{self.hostname}".')
            return False

        if cached_ip is None or cached_ip == current_ip:
            return False

        print(f'Host "{self.hostname}":', cached_ip, '→', current_ip,
              flush=True)
        return True

    def gateway_unreachable(self):
        """Pings the gateway to check if it is (un)reachable."""
        if self.gateway is None:
            error('No gateway specified, cannot ping. Assuming not reachable.')
            return True

        command = (PING, '-c', '3', '-W', '3', self.gateway)

        try:
            check_call(command, stdout=DEVNULL, stderr=DEVNULL)
        except CalledProcessError:
            print(f'Gateway "{self.gateway}" is not reachable.', flush=True)
            return True

        return False

    def reset(self):
        """Resets the interface."""
        command = (WG, 'set', self.interface, 'peer', self.pubkey, 'endpoint',
                   self.endpoint)

        try:
            check_call(command)
        except CalledProcessError:
            error('Resetting of interface failed.')
            return False

        print('Interface reset.', flush=True)
        return True

    def check(self, cache):
        """Checks, whether the WireGuard connection is still intact."""
        if self.ip_changed(cache) or self.gateway_unreachable():
            self.reset()


if __name__ == '__main__':
    main()
