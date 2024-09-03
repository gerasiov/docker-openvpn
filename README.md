# docker-openvpn

A Docker-based OpenVPN hosting/management system inspired by [kylemanna/docker-openvpn](https://github.com/kylemanna/docker-openvpn).

## Overview

This project provides an easy-to-use Docker container for setting up and managing an OpenVPN server. The Docker image is hosted on Docker Hub as `gerasiov/openvpn`. This tool simplifies the process of creating and managing OpenVPN servers and clients, with a variety of configurable options.

## Repository

GitHub: [gerasiov/docker-openvpn](https://github.com/gerasiov/docker-openvpn)

## Docker Image

Docker Hub: `gerasiov/openvpn`

## Quick Start

To quickly start an OpenVPN server, use the following command:

Initialize the OpenVPN server configuration (see below for more options):
```sh
docker run --rm -it -v /srv/services/openvpn:/data gerasiov/openvpn init --server vpn.example.com --port 7777 --no-ca-pass
```

You can always modify the server configuration by calling `init` again with different options. `init --help` will show you all available options and current default (loaded from config). 

Create a new client certificate:
```sh
docker run --rm -it -v /srv/services/openvpn:/data gerasiov/openvpn new-client client1
```

Generate a client configuration file (save it as `client1.ovpn` to use with an OpenVPN client):
```sh
docker run --rm -it -v /srv/services/openvpn:/data gerasiov/openvpn get-client-config client1
```

Start the OpenVPN server:
```sh
docker run -v /srv/services/openvpn:/data --cap-add=NET_ADMIN -p 7777:1194/udp gerasiov/openvpn 
```

## Usage

The main control script supports several commands for managing the OpenVPN server and clients. Below is a detailed help message for the main script and individual commands.

### Initialize OpenVPN Server

To initialize the OpenVPN server, use the `init` command with the required options.

```sh
docker run --rm -it  gerasiov/openvpn init --help
```

```
usage: control init [-h] [--ca-pass | --no-ca-pass] --server SERVER
                    [--protocol {udp,udp6,tcp,tcp6}] [--port PORT]
                    [--ipv6 | --no-ipv6] [--network NETWORK]
                    [--network6 NETWORK6] [--device {tun,tap}]
                    [--interface INTERFACE] [--nat | --no-nat]
                    [--nat6 | --no-nat6] [--comp-lzo | --no-comp-lzo]
                    [--no-dns-servers | --dns-server DNS_SERVERS]
                    [--duplicate-cn | --no-duplicate-cn]
                    [--block-outside-dns | --no-block-outside-dns]
                    [--client-to-client | --no-client-to-client]
                    [--default-route | --no-default-route]
                    [--default-route6 | --no-default-route6]
                    [--no-routes | --route ROUTES]
                    [--no-route6s | --route6 ROUTE6S]
                    [--no-extra-server-configs | --extra-server-config EXTRA_SERVER_CONFIGS]
                    [--no-extra-client-configs | --extra-client-config EXTRA_CLIENT_CONFIGS]

options:
  -h, --help            show this help message and exit
  --ca-pass             Require password for CA key (default)
  --no-ca-pass          Disable ca-pass
  --server SERVER       Server name
  --protocol {udp,udp6,tcp,tcp6}
                        Server protocol (default: udp)
  --port PORT           Server port (default: 1194)
  --ipv6                Enable IPv6 support
  --no-ipv6             Disable ipv6 (default)
  --network NETWORK     Network CIDR to use (default: 172.30.0.0/16)
  --network6 NETWORK6   IPv6 network CIDR to use (generate ULA if unset)
  --device {tun,tap}    Device to use (default: tun)
  --interface INTERFACE
                        Interface to use (default: eth0)
  --nat                 NAT (masquerade) traffic from clients to the internet
                        (default)
  --no-nat              Disable nat
  --nat6                NAT (masquerade) IPv6 traffic from clients to the
                        internet (equal to --nat if unset) (default: unset)
  --no-nat6             Disable nat6
  --comp-lzo            Enable LZO compression (DEPRECATED)
  --no-comp-lzo         Disable comp-lzo (default)
  --no-dns-servers      Clear dns-server
  --dns-server DNS_SERVERS
                        DNS server to use (default: ['8.8.8.8', '1.1.1.1'])
  --duplicate-cn        Allow multiple clients with same CN
  --no-duplicate-cn     Disable duplicate-cn (default)
  --block-outside-dns   Block DNS outside of tunnel (default)
  --no-block-outside-dns
                        Disable block-outside-dns
  --client-to-client    Enable client-to-client communication
  --no-client-to-client
                        Disable client-to-client (default)
  --default-route       Push default IPv4 route to clients (default)
  --no-default-route    Disable default-route
  --default-route6      Push default IPv6 route to clients (equal to
                        --default-route if unset) (default: unset)
  --no-default-route6   Disable default-route6
  --no-routes           Clear route
  --route ROUTES        Additional IPv4 route to push to clients (default: [])
  --no-route6s          Clear route6
  --route6 ROUTE6S      Additional IPv6 route to push to clients (default: [])
  --no-extra-server-configs
                        Clear extra-server-config
  --extra-server-config EXTRA_SERVER_CONFIGS
                        Extra server configuration (default: [])
  --no-extra-client-configs
                        Clear extra-client-config
  --extra-client-config EXTRA_CLIENT_CONFIGS
                        Extra client configuration (default: [])
```

### Creating a New Client

To create a new client certificate, use the `new-client` command with the required options.

```sh
docker run --rm -it gerasiov/openvpn new-client <client_name>
```

```
usage: control new-client [-h] [--key-pass | --no-key-pass] client_name

positional arguments:
  client_name    Client name

options:
  -h, --help     show this help message and exit
  --key-pass     Require password for private key
  --no-key-pass  Disable key-pass (default)
```

### Revoking a Client

To revoke a client certificate, use the `revoke-client` command with the client name.

```sh
docker run --rm -it gerasiov/openvpn revoke-client <client_name>
```

### Renewing a Client

To renew a client certificate, use the `renew-client` command with the client name.

```sh
docker run --rm -it gerasiov/openvpn renew-client <client_name>
```

### Listing Clients

To list all clients, use the `list-clients` command.

```sh
docker run --rm -it gerasiov/openvpn list-clients
```

### Showing a Client Certificate

To show a client's certificate, use the `show-client` command with the client name.

```sh
docker run --rm -it gerasiov/openvpn show-client <client_name>
```

### Getting a Client Configuration

To get a client configuration file, use the `get-client-config` command with the client name.

```sh
docker run --rm -it gerasiov/openvpn get-client-config <client_name>
```

## IPv6 Support
### IPv6 server address
To allow connections to the OpenVPN server over IPv6, specify `--proto udp6` or `--proto tcp6` when initializing the server. The server will listen on both IPv4 and IPv6 addresses.

### IPv6 network inside the tunnel
To enable IPv6 support inside the tunnel, specify `--ipv6` parameter when initializing the server. Take a note, that most options (nat, default-route, routes, etc.) could be set for IPv6 separately from IPv4.

### Recommended docker configuration for IPv6 support
To enable IPv6 support for the Docker daemon, add the following configuration to the Docker daemon configuration file (`/etc/docker/daemon.json`):
```json
{
  "experimental": true,
  "ipv6": true,
  "ip6tables": true,
  "fixed-cidr-v6": "fd00:1::/64"
}
```

It is also recommended to disable docker's userland proxy for better performance and compatibility with IPv6. Add the following configuration to the Docker daemon configuration file (`/etc/docker/daemon.json`):
```json
  "userland-proxy": false,
```
 
When starting the docker container you might have to enable IPv6 forwarding in it with the following docker run options:
```sh
 --sysctl net.ipv6.conf.default.disable_ipv6=0 --sysctl net.ipv6.conf.all.forwarding=1
```
so the full command to start the container with IPv6 support would be:
```sh
docker run -v /srv/services/openvpn:/data --cap-add=NET_ADMIN --sysctl net.ipv6.conf.default.disable_ipv6=0 --sysctl net.ipv6.conf.all.forwarding=1 -p 7777:1194/udp gerasiov/openvpn 
```

### IPv6 support with docker-compose
When using docker-compose you will need to add the following to the service configuration:
```yaml
    sysctls:
      - net.ipv6.conf.default.disable_ipv6=0
      - net.ipv6.conf.all.forwarding=1
```
and possibly use default brigde network, configured in previous section, as the service network.
```yaml
    network_mode: bridge
```
so the full service configuration would be:
```yaml
  openvpn:
    image: gerasiov/openvpn
    restart: unless-stopped
    ports:
      - "7777:1194/udp"
    cap_add:
      - NET_ADMIN
    sysctls:
      - net.ipv6.conf.default.disable_ipv6=0
      - net.ipv6.conf.all.forwarding=1
    volumes:
      - /srv/services/openvpn:/data
    network_mode: bridge
```

## Contributions

Contributions are welcome! Please submit pull requests or open issues on the [GitHub repository](https://github.com/gerasiov/docker-openvpn).

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](https://github.com/gerasiov/docker-openvpn/blob/main/LICENSE) file for details.