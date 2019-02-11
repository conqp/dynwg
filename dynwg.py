#! /usr/bin/env python3
"""WireGuard over systemd-networkd DynDNS watchdog daemon."""

from configparser import ConfigParser
from contextlib import suppress
from json import dump, load
from pathlib import Path
from socket import gaierror, gethostbyname
from subprocess import run
from sys import stderr


CACHE = Path('/var/cache/dynwg.json')
SYSTEMD_NETWORK = Path('/etc/systemd/network')
NETDEVS = SYSTEMD_NETWORK.glob('*.netdev')
WG = '/usr/bin/wg'


def is_wg_client(netdev):
    """Checks whether the netdev is a WireGuard client interface."""

    try:
        _ = netdev['WireGuardPeer']['Endpoint']     # Check if endpoint is set.
        return netdev['NetDev']['Kind'] == 'wireguard'
    except KeyError:
        return False


def get_changed_ip(cache, host):
    """Determines whether the IP address
    of the specified host has changed.
    """

    try:
        current_ip = gethostbyname(host)
    except gaierror:
        print(f'Host "{host}" cannot be resolved.', file=stderr, flush=True)
        return False

    try:
        cached_ip = cache[host]
    except KeyError:
        return False
    else:
        print(f'Host "{host}":', cached_ip, '→', current_ip, flush=True)
        return False if cached_ip == current_ip else current_ip
    finally:
        cache[host] = current_ip


def check(cache, netdev):
    """Checks the respective *.netdev config."""

    endpoint = netdev['WireGuardPeer']['Endpoint']
    host, _ = endpoint.split(':')   # Discard port.
    changed_ip = get_changed_ip(cache, host)

    if changed_ip:
        interface = netdev['NetDev']['Name']
        pubkey = netdev['WireGuardPeer']['PublicKey']
        run((WG, 'set', interface, 'peer', pubkey, 'endpoint', changed_ip))


def main():
    """Daemon's main loop."""

    with Cache(CACHE) as cache:
        for path in NETDEVS:
            netdev = ConfigParser()
            netdev.read(path)

            if is_wg_client(netdev):
                print('Checking:', path, flush=True)
                check(cache, netdev)


class Cache(dict):
    """Host name → IP address cache."""

    def __new__(cls, _):
        return super().__new__(cls)

    def __init__(self, path):
        super().__init__()
        self.path = path

    def __enter__(self):
        self.load()
        return self

    def __exit__(self, *_):
        self.dump()

    def load(self):
        """Loads the cache."""
        with suppress(FileNotFoundError):
            with self.path.open('r') as file:
                self.update(load(file))

    def dump(self):
        """Dumps the cache."""
        with self.path.open('w') as file:
            dump(self, file, indent=2)


if __name__ == '__main__':
    main()
