#! /usr/bin/env python3
"""WireGuard over systemd-networkd DynDNS watchdog daemon."""

from configparser import ConfigParser
from contextlib import suppress
from json import dump, load
from pathlib import Path
from socket import gaierror, gethostbyname
from subprocess import DEVNULL, CalledProcessError, check_call
from sys import stderr


CACHE = Path('/var/cache/dynwg.json')
SYSTEMD_NETWORK = Path('/etc/systemd/network')
NETDEVS = SYSTEMD_NETWORK.glob('*.netdev')
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


def configfiles():
    """Yields the available config files."""

    for path in NETDEVS:
        netdev = ConfigParser(strict=False)
        netdev.read(path)

        if is_wg_client(netdev):
            name = path.stem
            path = path.parent.joinpath(f'{name}.network')
            network = ConfigParser(strict=False)
            yield (name, netdev, network)


def ip_changed(host, cache):
    """Determines whether the IP address
    of the specified host has changed.
    """

    try:
        current_ip = gethostbyname(host)
    except gaierror:
        error(f'Cannot resolve host: "{host}".')
        cache.delete(host)
        return False

    try:
        cached_ip = cache[host]
    except KeyError:
        return False
    else:
        print(f'Host "{host}":', cached_ip, '→', current_ip, flush=True)
        return cached_ip != current_ip
    finally:
        cache[host] = current_ip


def gateway_unreachable(gateway):
    """Pings the respective gateway to check if it is unreachable."""

    if not gateway:
        error('No gateway specified, cannot ping. Assuming not reachable.')
        return True

    command = (PING, '-c', '3', '-W', '3', gateway)

    try:
        check_call(command, stdout=DEVNULL, stderr=DEVNULL)
    except CalledProcessError:
        return True

    return False


def reset(netdev, host, cache):
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

    try:
        current_ip = cache[host]
    except KeyError:
        error('Current IP unknown. Cannot reset connection.')
        return False

    command = (WG, 'set', interface, 'peer', pubkey, 'endpoint', current_ip)

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

    try:
        gateway = network['Route']['Gateway']
    except KeyError:
        gateway = None

    if ip_changed(host, cache) or gateway_unreachable(gateway):
        return reset(netdev, host, cache)

    return True


def main():
    """Daemon's main loop."""

    with Cache(CACHE) as cache:
        for name, netdev, network in configfiles():
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

    def delete(self, key):
        """Deletes the respective key."""
        with suppress(KeyError):
            del self[key]
            self.dirty = True

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
