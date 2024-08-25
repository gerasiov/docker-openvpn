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
usage: control init [-h] [--ca-pass | --no-ca-pass] --server SERVER [--protocol {udp,tcp}]
                    [--port PORT] [--network NETWORK] [--device {tun,tap}]
                    [--interface INTERFACE] [--nat | --no-nat] [--comp-lzo | --no-comp-lzo]
                    [--no-dns-servers | --dns-server DNS_SERVERS]
                    [--duplicate-cn | --no-duplicate-cn]
                    [--block-outside-dns | --no-block-outside-dns]
                    [--client-to-client | --no-client-to-client]
                    [--default-route | --no-default-route] [--no-routes | --route ROUTES]
                    [--no-extra-server-configs | --extra-server-config EXTRA_SERVER_CONFIGS]
                    [--no-extra-client-configs | --extra-client-config EXTRA_CLIENT_CONFIGS]

options:
  -h, --help            show this help message and exit
  --ca-pass             Require password for CA key (default)
  --no-ca-pass          Disable ca-pass
  --server SERVER       Server name
  --protocol {udp,tcp}  Server protocol (default: udp)
  --port PORT           Server port (default: 1194)
  --network NETWORK     Network CIDR to use (default: 172.30.0.0/16)
  --device {tun,tap}    Device to use (default: tun)
  --interface INTERFACE
                        Interface to use (default: eth0)
  --nat                 NAT (masquerade) traffic from clients to the internet (default)
  --no-nat              Disable nat
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
  --default-route       Push default route to clients (default)
  --no-default-route    Disable default-route
  --no-routes           Clear route
  --route ROUTES        Additional route to push to clients (default: [])
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

## Contributions

Contributions are welcome! Please submit pull requests or open issues on the [GitHub repository](https://github.com/gerasiov/docker-openvpn).

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](https://github.com/gerasiov/docker-openvpn/blob/main/LICENSE) file for details.