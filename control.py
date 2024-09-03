#!/usr/bin/env python
#
# This is a control script for the docker-openvpn container.
# It is used to initialize the OpenVPN server, create and revoke clients,
# and get client configurations.
#
# Copyright 2024 Alexander Gerasiov <a@gerasiov.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import ipaddress
import json
import stat
import sys
from dataclasses import dataclass, field, InitVar
import argparse
import logging
import os
import subprocess

logger = logging.getLogger(__name__)

DATA_DIR = os.environ.get('OVPN_WORKDIR', './data')
OPENVPN_DIR = os.path.join(DATA_DIR, 'openvpn')
EASYRSA_PKI = os.path.join(DATA_DIR, 'pki')

EASYRSA = ['easyrsa', f'--pki={EASYRSA_PKI}', '--batch', '--silent']
SERVER_EASYRSA_ID = '_server'


def parse_cidr(cidr: str) -> tuple[str, str]:
    network = ipaddress.ip_network(cidr)
    return str(network.network_address), str(network.netmask)


def normalize_address(address: str) -> str:
    if '/' in address:
        return ' '.join(parse_cidr(address))
    else:
        return address


@dataclass
class Config:
    config_file: InitVar[str]

    server: str | None = None
    network: str = '172.30.0.0/16'
    routes: list[str] = field(default_factory=list)
    protocol: str = 'udp'
    port: int = 1194
    device: str = 'tun'
    interface: str = 'eth0'
    nat: bool = True
    dns_servers: list[str] = field(default_factory=lambda: ['8.8.8.8', '1.1.1.1'])
    client_to_client: bool = False
    duplicate_cn: bool = False
    comp_lzo: bool = False
    default_route: bool = True
    block_outside_dns: bool = True
    extra_server_configs: list[str] = field(default_factory=list)
    extra_client_configs: list[str] = field(default_factory=list)

    def __post_init__(self, config_file: str):
        self.update(config_file=config_file, env=os.environ.__dict__)

    def update_attr(self, attr: str, value):
        if value is None:
            return

        if self.__dict__[attr] is None:
            self.__dict__[attr] = value
            return

        attr_type = type(self.__dict__[attr])
        value_type = type(value)
        if attr_type != value_type:
            if attr_type == bool:
                if value_type == str:
                    value = value.lower() in ['yes', 'true', '1']
                else:
                    value = bool(value)
            elif attr_type == list:
                if value_type == str:
                    value = value.split(',')
                else:
                    value = list(value)
            elif attr_type == str:
                value = str(value)
            elif attr_type == int:
                value = int(value)
            else:
                raise ValueError(f'Could not update attribute {attr} of type {attr_type} '
                                 f'to value {value} of type {value_type}')
        self.__dict__[attr] = value

    def validate(self) -> None:
        # Check for required attributes
        if not self.server:
            raise ValueError('Server\'s hostname not set')
        if '/' not in self.network:
            raise ValueError('Network should be in CIDR format')

    def update(self,
               config_file: str | None = None,
               env: dict | None = None,
               args: argparse.Namespace | None = None):
        # Load config file
        if config_file and os.path.exists(config_file):
            with open(config_file, encoding='utf-8') as f:
                config_data = json.load(f)
                for key in self.__dict__:
                    self.update_attr(key, config_data.get(key))

        if env:
            # Load environment variables
            for key in self.__dict__:
                env_value = env.get(f"OVPN_{key.upper()}")
                self.update_attr(key, env_value)

        if args:
            # Load command line arguments
            for key in self.__dict__:
                self.update_attr(key, args.__dict__.get(key))

    def save(self, config_file: str) -> None:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(self.__dict__, f, indent=2)


def run_command(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    logger.debug(f'Running command: {" ".join(command)}')
    if 'check' not in kwargs:
        kwargs['check'] = True
    return subprocess.run(command, **kwargs)


def init_easy_rsa(config: Config, args: argparse.Namespace):
    logger.info('Initializing EasyRSA.')
    no_pass = ['--no-pass'] if not args.ca_pass else []
    if not os.path.exists(EASYRSA_PKI):
        run_command([*EASYRSA, 'init-pki'])
        os.chmod(EASYRSA_PKI, 0o711)
    if not os.path.exists(os.path.join(EASYRSA_PKI, 'ca.crt')):
        run_command([*EASYRSA, *no_pass, 'build-ca'])
    if not os.path.exists(os.path.join(EASYRSA_PKI, 'dh.pem')):
        run_command([*EASYRSA, 'gen-dh'])
    run_command([*EASYRSA, 'gen-crl'])
    os.chmod(os.path.join(EASYRSA_PKI, 'crl.pem'), 0o644)
    if not os.path.exists(os.path.join(EASYRSA_PKI, 'reqs', f'{SERVER_EASYRSA_ID}.req')):
        run_command([*EASYRSA, f'--req-cn={config.server}', 'gen-req', SERVER_EASYRSA_ID, 'nopass'])
    if not os.path.exists(os.path.join(EASYRSA_PKI, 'issued', f'{SERVER_EASYRSA_ID}.crt')):
        run_command([*EASYRSA, '--batch', 'sign-req', 'server', SERVER_EASYRSA_ID])


def init_openvpn(config: Config):
    logger.info('Initializing OpenVPN server configuration.')
    if not os.path.exists(OPENVPN_DIR):
        logger.info(f'Initializing OpenVPN directory {OPENVPN_DIR}.')
        os.makedirs(OPENVPN_DIR)
    else:
        logger.warning(f'OpenVPN directory {OPENVPN_DIR} already exists, overwriting configuration...')
        logger.warning('Old client configuration could became invalid, consider regenerating them.')
    if not os.path.exists(os.path.join(OPENVPN_DIR, 'ta.key')):
        run_command(['openvpn', '--genkey', 'secret', 'ta.key'], cwd=OPENVPN_DIR)

    logger.info('Creating server configuration.')

    config_options = [
        f'server {normalize_address(config.network)}',
        'verb 3',
        f'proto {config.protocol}',
        'port 1194',
        f'dev {config.device}0',
        'topology subnet',

        'keepalive 10 60',
        'persist-key',
        'persist-tun',

        f'ca {EASYRSA_PKI}/ca.crt',
        f'key {EASYRSA_PKI}/private/{SERVER_EASYRSA_ID}.key',
        f'cert {EASYRSA_PKI}/issued/{SERVER_EASYRSA_ID}.crt',
        f'dh {EASYRSA_PKI}/dh.pem',
        f'tls-auth {OPENVPN_DIR}/ta.key 0',
        f'crl-verify {EASYRSA_PKI}/crl.pem',

        'status /tmp/openvpn-status.log',
        'user nobody',
        'group nogroup',
    ]
    for subnet in config.routes:
        subnet_split = subnet.split(' ')
        subnet = ' '.join([normalize_address(subnet_split[0]), *subnet_split[1:]])
        config_options.append(f'push "route {subnet}"')

    for dns_server in config.dns_servers:
        config_options.append(f'push "dhcp-option DNS {dns_server}"')

    if config.client_to_client:
        config_options.append('client-to-client')

    if config.duplicate_cn:
        config_options.append('duplicate-cn')

    if config.comp_lzo:
        logger.warning('LZO compression is deprecated and not recommended.')
        config_options.append('comp-lzo yes')
        config_options.append('push "comp-lzo yes"')

    if config.block_outside_dns:
        config_options.append('push "block-outside-dns"')

    config_options.extend(config.extra_server_configs)

    with open(os.path.join(OPENVPN_DIR, 'server.conf'), 'w', encoding='utf-8') as f:
        f.writelines(line + '\n' for line in config_options)


def init(config: Config, args: argparse.Namespace) -> int:
    if args.ca_pass and not sys.stdin.isatty():
        logger.error('CA password required, but stdin is not a tty.')
        return 1
    init_easy_rsa(config, args)
    init_openvpn(config)
    logger.info('Initialization complete.')
    return 0


def start(config: Config) -> int:
    logger.info('Preparing environment...')
    os.makedirs('/dev/net', exist_ok=True)
    if not os.path.exists('/dev/net/tun'):
        os.mknod('/dev/net/tun', mode=stat.S_IFCHR, device=os.makedev(10, 200))

    with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
        if f.read().strip() != '1':
            logger.warning('IP forwarding is not enabled')

    if config.nat:
        # silently remove existing iptables rule if exists
        run_command(['iptables',
                     '-t', 'nat',
                     '-D', 'POSTROUTING',
                     '-s', config.network,
                     '-o', config.interface,
                     '-j', 'MASQUERADE'],
                    check=False,
                    stderr=subprocess.DEVNULL)
        run_command(['iptables',
                     '-t', 'nat',
                     '-A', 'POSTROUTING',
                     '-s', config.network,
                     '-o', config.interface,
                     '-j', 'MASQUERADE'])

    logger.info('Starting OpenVPN server:')
    return os.execvp('openvpn', ['openvpn', '--config', f'{OPENVPN_DIR}/server.conf'])


def new_client(config: Config, client_name: str, key_pass) -> int:
    if key_pass and not sys.stdin.isatty():
        logger.error('Key password required, but stdin is not a tty.')
        return 1

    # TODO: Handle already existing clients
    logger.info(f'Creating new client {client_name}')
    if not os.path.exists(os.path.join(EASYRSA_PKI, 'reqs', f'{client_name}.req')):
        run_command([*EASYRSA, f'--req-cn={client_name}', 'gen-req', client_name] +
                    (['nopass'] if not key_pass else []))
    if not os.path.exists(os.path.join(EASYRSA_PKI, 'issued', f'{client_name}.crt')):
        run_command([*EASYRSA, 'sign-req', 'client', client_name])

    return 0


def revoke_client(config: Config, client_name: str) -> int:
    logger.info(f'Revoking client {client_name}.')
    if not os.path.exists(os.path.join(EASYRSA_PKI, 'issued', f'{client_name}.crt')):
        logger.error(f'Client {client_name} does not exist')
        return 1
    run_command([*EASYRSA, 'revoke', client_name])
    run_command([*EASYRSA, 'gen-crl'])
    return 0


def renew_client(config: Config, client_name: str) -> int:
    logger.info(f'Renewing client {client_name}.')
    if not os.path.exists(os.path.join(EASYRSA_PKI, 'issued', f'{client_name}.crt')):
        logger.error(f'Client {client_name} does not exist')
        return 1
    run_command([*EASYRSA, 'renew', client_name])
    return 0


def list_clients(config: Config) -> int:
    logger.info('Listing clients:')
    clients = [f.rsplit('.', 1)[0] for f in
               os.listdir(os.path.join(EASYRSA_PKI, 'issued')) if f.endswith('.crt')]
    for client in clients:
        if client == SERVER_EASYRSA_ID:
            continue

        verify_result = run_command(['openssl', 'verify',
                                     '-crl_check_all',
                                     '-purpose', 'sslclient',
                                     '-CAfile', f'{EASYRSA_PKI}/ca.crt',
                                     '-CRLfile', f'{EASYRSA_PKI}/crl.pem',
                                     f'{EASYRSA_PKI}/issued/{client}.crt'],
                                    stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, check=False)

        expiration_date = run_command(
            [
                'openssl', 'x509',
                '-noout',
                '-enddate',
                '-in', f'{EASYRSA_PKI}/issued/{client}.crt'
            ],
            stdout=subprocess.PIPE
        ).stdout.decode('utf-8').split('=')[1].strip()
        if verify_result.returncode == 0:
            print(f'{client}, valid till {expiration_date}')
        else:
            for line in verify_result.stderr.decode('utf-8').split('\n'):
                if line.startswith('error'):
                    error_code = line.split()[1]
                    if error_code == '10':
                        print(f'{client}, expired on {expiration_date}')
                        break
                    if error_code == '23':
                        print(f'{client}, revoked')
                        break
                    if error_code == '26':
                        print(f'{client}, not sslclient certificate')
                        break
            else:
                print(f'{client}, invalid (unknown openssl error)')
    return 0


def show_client(config: Config, client_name: str) -> int:
    logger.info(f'Showing client {client_name}:')
    if not os.path.exists(os.path.join(EASYRSA_PKI, 'issued', f'{client_name}.crt')):
        logger.error(f'Client {client_name} does not exist')
        return 1
    with open(os.path.join(EASYRSA_PKI, 'issued', f'{client_name}.crt'), encoding='utf-8') as f:
        print(f.read())
    return 0


def get_client_config(config: Config, client_name: str) -> int:
    logger.info(f'Getting client config for {client_name}:')
    if not os.path.exists(os.path.join(EASYRSA_PKI, 'issued', f'{client_name}.crt')):
        logger.error(f'Client {client_name} does not exist')
        return 1

    config_options = [
        'client',
        'nobind',
        f'dev {config.device}',
        f'remote {config.server} {config.port} {config.protocol}',
        'remote-cert-tls server',
        'key-direction 1'
    ]
    config_options.extend(config.extra_client_configs)
    if config.default_route:
        config_options.append('redirect-gateway def1')

    sys.stdout.writelines(line + '\n' for line in config_options)

    for key, file in {
        'key': f'{EASYRSA_PKI}/private/{client_name}.key',
        'cert': f'{EASYRSA_PKI}/issued/{client_name}.crt',
        'ca': f'{EASYRSA_PKI}/ca.crt',
        'tls-auth': f'{OPENVPN_DIR}/ta.key',
    }.items():
        sys.stdout.write(f'<{key}>\n')
        with open(file, encoding='utf-8') as f:
            sys.stdout.write(f.read())
        sys.stdout.write(f'</{key}>\n')

    return 0


def parse_args(config: Config) -> argparse.Namespace:
    class replace_append(argparse.Action):    # noqa N801
        def __call__(self, parser, namespace, values, option_string=None):
            if getattr(namespace, self.dest, None) is None:
                setattr(namespace, self.dest, [])
            getattr(namespace, self.dest).append(values)

    def add_argument(_parser: argparse.ArgumentParser, arg: str, **kwargs):
        config_var = arg.replace('-', '_')
        if kwargs.get('action') == 'append':
            kwargs['action'] = replace_append
            config_var += 's'
            kwargs['dest'] = config_var
        if config_var in config.__dict__:
            default = config.__dict__[config_var]
            if default is None:
                kwargs['required'] = True
            else:
                kwargs['default'] = config.__dict__[config_var]

        if 'default' in kwargs:
            kwargs['help'] = f'{kwargs["help"]} (default: {kwargs["default"]})'

        if kwargs.get('action') == replace_append:
            _parser = _parser.add_mutually_exclusive_group()  # type: ignore[assignment]
            _parser.add_argument(f'--no-{arg}s',
                                 action='store_const',
                                 const=[],
                                 dest=config_var,
                                 help=f'Clear {arg}')
        _parser.add_argument(f'--{arg}', **kwargs)

    def add_tristate_argument(_parser: argparse.ArgumentParser, arg: str, **kwargs):
        _group = _parser.add_mutually_exclusive_group()
        arg_var = arg.replace('-', '_')
        default = config.__dict__.get(arg_var, kwargs.get('default'))
        _help = kwargs['help']

        if default is None:
            kwargs['help'] = f'{_help} (default: unset)'

        # Add --arg option
        kwargs['default'] = default
        if default:
            kwargs['help'] = f'{_help} (default)'
        _group.add_argument(f'--{arg}',
                            dest=arg_var,
                            action='store_true',
                            **kwargs)

        # Add --no-arg option
        if default is not None:
            default = not default
        _help = f'Disable {arg}'
        kwargs['help'] = _help
        kwargs['default'] = default
        if default:
            kwargs['help'] = f'{_help} (default)'
        _group.add_argument(f'--no-{arg}',
                            action='store_false',
                            dest=arg_var,
                            **kwargs)

    parser = argparse.ArgumentParser(description='docker-openvpn control script')
    parser.add_argument('--verbose', '-v',
                        action='store_true',
                        help='Enable verbose logging',
                        default=False)
    action_parsers = parser.add_subparsers(dest='action',
                                           help='Action to perform',
                                           required=True)
    init_parser = action_parsers.add_parser('init',
                                            help='Initialize OpenVPN server')

    add_tristate_argument(init_parser,
                          'ca-pass',
                          help='Require password for CA key',
                          default=True)

    add_argument(init_parser,
                 'server',
                 help='Server name')
    add_argument(init_parser,
                 'protocol',
                 choices=['udp', 'tcp'],
                 help='Server protocol')
    add_argument(init_parser,
                 'port',
                 help='Server port')
    add_argument(init_parser,
                 'network',
                 help='Network CIDR to use')
    add_argument(init_parser,
                 'device',
                 choices=['tun', 'tap'],
                 help='Device to use')
    add_argument(init_parser,
                 'interface',
                 help='Interface to use')
    add_tristate_argument(init_parser,
                          'nat',
                          help='NAT (masquerade) traffic from clients to the internet')
    add_tristate_argument(init_parser,
                          'comp-lzo',
                          help='Enable LZO compression (DEPRECATED)')

    add_argument(init_parser,
                 'dns-server',
                 help='DNS server to use',
                 action='append')
    add_tristate_argument(init_parser,
                          'duplicate-cn',
                          help='Allow multiple clients with same CN')
    add_tristate_argument(init_parser,
                          'block-outside-dns',
                          help='Block DNS outside of tunnel')
    add_tristate_argument(init_parser,
                          'client-to-client',
                          help='Enable client-to-client communication')
    add_tristate_argument(init_parser,
                          'default-route',
                          help='Push default route to clients')
    add_argument(init_parser,
                 'route',
                 help='Additional route to push to clients',
                 action='append')

    add_argument(init_parser,
                 'extra-server-config',
                 help='Extra server configuration',
                 action='append')
    add_argument(init_parser,
                 'extra-client-config',
                 help='Extra client configuration',
                 action='append')

    start_parser = action_parsers.add_parser('start',
                                             help='Start OpenVPN server')

    new_client_parser = action_parsers.add_parser('new-client',
                                                  help='Create new client certificate')
    new_client_parser.add_argument('client_name',
                                   help='Client name')
    add_tristate_argument(new_client_parser,
                          'key-pass',
                          help='Require password for private key',
                          default=False)

    revoke_client_parser = action_parsers.add_parser('revoke-client',
                                                     help='Revoke client certificate')
    revoke_client_parser.add_argument('client_name',
                                      help='Client name')

    renew_client_parser = action_parsers.add_parser('renew-client',
                                                    help='Renew client certificate')
    renew_client_parser.add_argument('client_name',
                                     help='Client name')

    list_clients_parser = action_parsers.add_parser('list-clients',
                                                    help='List clients')

    show_client_parser = action_parsers.add_parser('show-client',
                                                   help='Show client certificate')
    show_client_parser.add_argument('client_name',
                                    help='Client name')

    get_client_config_parser = action_parsers.add_parser('get-client-config',
                                                         help='Get client config')
    get_client_config_parser.add_argument('client_name',
                                          help='Client name')

    return parser.parse_args()


def main():
    config = Config(os.path.join(DATA_DIR, 'control.conf'))
    args = parse_args(config)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(message)s")

    logger.info('Starting docker-openvpn script')
    logger.debug(f'Action: {args.action}')

    if not os.path.exists(DATA_DIR):
        logger.error(f'Data directory {DATA_DIR} does not exist, may be missing volume mount.')
        return 1

    if args.action == 'init':
        config.update(args=args)
        config.validate()
        config.save(os.path.join(DATA_DIR, 'control.conf'))
        return init(config, args)

    if not os.path.exists(EASYRSA_PKI) or not os.path.exists(OPENVPN_DIR):
        logger.error('OpenVPN server was not initialized, run init first.')
        return 1

    if args.action == 'start':
        return start(config)
    if args.action == 'new-client':
        return new_client(config, args.client_name, args.key_pass)
    if args.action == 'revoke-client':
        return revoke_client(config, args.client_name)
    if args.action == 'renew-client':
        return renew_client(config, args.client_name)
    if args.action == 'list-clients':
        return list_clients(config)
    if args.action == 'show-client':
        return show_client(config, args.client_name)
    if args.action == 'get-client-config':
        return get_client_config(config, args.client_name)

    raise NotImplementedError(f'Action {args.action} not implemented.')


if __name__ == '__main__':
    sys.exit(main())
