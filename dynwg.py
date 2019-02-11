#! /usr/bin/env python3
"""WireGuard over systemd-networkd DynDNS watchdog daemon."""

from configparser import ConfigParser
from json import dump, load
from pathlib import Path
from socket import gaierror, gethostbyname
from subprocess import DEVNULL, CalledProcessError, check_call
from sys import stderr


CACHE = Path('/var/cache/dynwg.json')
SYSTEMD_NETWORK = Path('/etc/systemd/network')
NETDEVS = SYSTEMD_NETWORK.glob('*.netdev')
NETWORKS = SYSTEMD_NETWORK.glob('*.network')
PING = '/usr/bin/ping'
WG = '/usr/bin/wg'


def error(*msg):
    """Prints an error message."""

    print(*msg, file=stderr, flush=True)


def is_wg_client(netdev):
    """Checks whether the netdev is a WireGuard client interface."""

    try:
        _ = netdev['WireGuardPeer']['Endpoint']     # Check if endpoint is set.
        return netdev['NetDev']['Kind'] == 'wireguard'
    except KeyError:
        return False


def get_network(interface):
    """Returns the network configuration for the respective interface."""

    for path in NETWORKS:
        network = ConfigParser(strict=False)
        network.read(path)

        try:
            if network['Match']['Name'] == interface:
                return network
        except KeyError:
            continue

    return {}   # Return empty dict to allow subscription.


def configurations():
    """Yields the available configurations."""

    for path in NETDEVS:
        netdev = ConfigParser(strict=False)
        netdev.read(path)

        try:
            interface = netdev['NetDev']['Name']
        except KeyError:
            continue

        if is_wg_client(netdev):
            network = get_network(interface)
            yield (interface, netdev, network)


def ip_changed(host, cache):
    """Determines whether the IP address
    of the specified host has changed.
    """

    try:
        current_ip = gethostbyname(host)
    except gaierror:
        error(f'Cannot resolve host: "{host}".')
        return False

    cached_ip = cache.get(host)
    cache[host] = current_ip

    if cached_ip is None:
        return False

    print(f'Host "{host}":', cached_ip, '→', current_ip, flush=True)
    return cached_ip != current_ip


def gateway_unreachable(network):
    """Pings the respective gateway to check if it is unreachable."""

    try:
        gateway = network['Route']['Gateway']
    except KeyError:
        error('No gateway specified, cannot ping. Assuming not reachable.')
        return True

    command = (PING, '-c', '3', '-W', '3', gateway)

    try:
        check_call(command, stdout=DEVNULL, stderr=DEVNULL)
    except CalledProcessError:
        print(f'Gateway "{gateway}" is not reachable.', flush=True)
        return True

    return False


def reset(netdev, endpoint):
    """Resets the respective interface."""

    try:
        interface = netdev['NetDev']['Name']
    except KeyError:
        error('NetDev→Name not specified. Cannot reset interface.')
        return False

    try:
        pubkey = netdev['WireGuardPeer']['PublicKey']
    except KeyError:
        error('WireGuardPeer→PublicKey not specified. Cannot reset interface.')
        return False

    command = (WG, 'set', interface, 'peer', pubkey, 'endpoint', endpoint)

    try:
        check_call(command)
    except CalledProcessError:
        error('Resetting of interface failed.')
        return False

    return True


def check(netdev, network, cache):
    """Checks the respective *.netdev config."""

    try:
        endpoint = netdev['WireGuardPeer']['Endpoint']
    except KeyError:
        error('WireGuardPeer→Endpoint not specified. Cannot check host.')
        return False

    host, *_ = endpoint.split(':')  # Discard port.

    if ip_changed(host, cache) or gateway_unreachable(network):
        return reset(netdev, endpoint)

    return True


def main():
    """Daemon's main loop."""

    with Cache(CACHE) as cache:
        for name, netdev, network in configurations():
            print(f'Checking: {name}.', flush=True)
            check(netdev, network, cache)


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


if __name__ == '__main__':
    main()
