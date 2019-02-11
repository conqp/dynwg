#! /usr/bin/env python3
"""wg-systemd-networkd-wd.

    WireGuard over systemd-networkd DynDNS watchdog daemon.

Usage:
    wg-systemd-networkd-wd [options]

Options:
    --interval=<interval>, -i   Set the loop interval [default: 60].
    --help, -h                  Show this page.
"""
from configparser import ConfigParser
from contextlib import suppress
from json import JSONDecodeError, dump, load
from pathlib import Path
from socket import gaierror, gethostbyname
from subprocess import run
from sys import stderr


CACHE = Path('/var/cache/dynwg.json')
SYSTEMD_NETWORK = Path('/etc/systemd/network')
NETDEVS = SYSTEMD_NETWORK.glob('*.netdev')
WG = '/usr/bin/wg'


class Cache(dict):
    """Host name → IP address cache."""

    def __new__(cls, _):
        return super().__new__()

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
                with suppress(UnicodeDecodeError, JSONDecodeError):
                    self.update(load(file))

    def dump(self):
        """Dumps the cache."""
        with self.path.open('w') as file:
            dump(self, file, indent=2)


def is_wg(netdev):
    """Checks whether the netdev is a WireGuard interface."""

    try:
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
        return False if cached_ip == current_ip else current_ip
    finally:
        cache[host] = current_ip


def check(cache, netdev):
    """Checks the respective *.netdev config."""

    endpoint = netdev['WireGuardPeer']['Endpoint']
    host, _ = endpoint.split(':')
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

            if is_wg(netdev):
                check(cache, netdev)


if __name__ == '__main__':
    main()
