# dynwg
A simple, lightweight DynDNS watchdog for WireGuard via systemd-networkd.

## Caching
Runtime caching is performed in `/var/cache/dynwg.json`:

    {
      "myhost.mydyndnsprovider.com": "192.168.0.1",
      "anotherhost.otherdomain.com": "10.8.0.1"
    }

## Installation
For Arch Linux users there is an [AUR package](https://aur.archlinux.org/packages/dynwg/) available.  
You can also manually copy `dynwg.py` to `/usr/local/sbin/dynwg` and `dynwg.{service,timer}` to `/etc/systemd/system`. Be sure to change the `ExecStart=` setting in `dynwg.service` to the path where you copied `dynwg.py` to.

## Running
The daemon is run by enabling and starting `dynwg.timer`:

    systemctl enable --now dynwg.timer

Alternatively in can be invoked manually by executing `/usr/bin/dynwg` or `/usr/local/sbin/dynwg` respectively.
