# Web Socket Relay

Binary is from: https://github.com/isobit/ws-tcp-relay/releases/tag/v0.2.0

```shell
./ws-tcp-relay_linux_amd64 -b -p 9797 localhost:9798
```

Then patch the web server to relay the terminal input/output to `ws://localhost:9797` and connect to `localhost:9798` with pwntools.

On pwntools - check Python files in this directory
