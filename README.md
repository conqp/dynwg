# dynwg
A simple, lightweight DynDNS watchdog for WireGuard via systemd-networkd.

## Caching
Runtime caching is performed in-memory and dumped to `/var/cache/dynwg.json`:

    {
      "myhost.mydyndnsprovider.com": "192.168.0.1",
      "anotherhost.otherdomain.com": "10.8.0.1"
    }

You can force a cache dump during runtime by sending `SIGUSR1` to the dynwgd process.

## Installation
For Arch Linux users there is an [AUR package](https://aur.archlinux.org/packages/dynwg-git/) available.  
You can also manually copy `dynwg.py` to `/usr/local/sbin/dynwgd` and `dynwg@.service` to `/etc/systemd/system`. Be sure to change the `ExecStart=` setting in `dynwg@.service` to the path where you copied `dynwg.py` to.

## Running
The daemon is run by enabling and starting `dynwg@.service`:

    systemctl enable --now dynwg@60.service

Alternatively in can be invoked manually by running executing

    /usr/bin/dynwgd <interval>

or

    /usr/local/sbin/dynwgd <interval>

respectively.
