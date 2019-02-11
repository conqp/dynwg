# dynwg
A simple, lightweight DynDNS watchdog for WireGuard via systemd-networkd.

## Caching
Runtime caching is performed in `/var/cache/dynwg.json`:
```
{
    "myhost.mydyndnsprovider.com": "192.168.0.1",
    "anotherhost.otherdomain.com": "10.8.0.1"
}
```

## Running
The daemon is run by executing `dynwg`.
