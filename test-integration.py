#!/usr/bin/env python3
#
# Integration tests for docker-openvpn
# Tests various commands using docker run --rm -it
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

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    NC = '\033[0m'  # No Color


class IntegrationTests:
    """Integration tests for docker-openvpn"""
    
    def __init__(self, image_name: str, verbose: bool = False):
        self.image_name = image_name
        self.verbose = verbose
        self.test_data_dir = tempfile.mkdtemp(prefix='openvpn-test-')
        self.tests_passed = 0
        self.tests_failed = 0
        self.current_test_number = 0
        
    def cleanup(self):
        """Clean up test data directory"""
        print(f"{Colors.YELLOW}Cleaning up test data...{Colors.NC}")
        if os.path.exists(self.test_data_dir):
            # Fix permissions before cleanup using Docker
            try:
                self._run_docker_command(['sh', '-c', f'chown -R {os.getuid()}:{os.getgid()} /data'], 
                                        capture_output=True)
            except subprocess.CalledProcessError:
                pass
            shutil.rmtree(self.test_data_dir, ignore_errors=True)
    
    def _run_docker_command(self, args: list, capture_output: bool = False) -> subprocess.CompletedProcess:
        """Run a docker command with the openvpn image"""
        cmd = ['docker', 'run', '--rm', '-i', '-v', f'{self.test_data_dir}:/data', 
               self.image_name] + args
        
        if self.verbose:
            print(f"Running: {' '.join(cmd)}")
            return subprocess.run(cmd, text=True)
        else:
            if capture_output:
                return subprocess.run(cmd, capture_output=True, text=True)
            else:
                return subprocess.run(cmd, stdout=subprocess.DEVNULL, 
                                    stderr=subprocess.DEVNULL, text=True)
    
    def _check_file_exists_in_container(self, filepath: str) -> bool:
        """Check if a file exists inside the container's /data directory"""
        try:
            result = self._run_docker_command(['sh', '-c', f'test -f /data/{filepath}'], 
                                             capture_output=True)
            return result.returncode == 0
        except subprocess.CalledProcessError:
            return False
    
    def pass_test(self, message: str):
        """Mark a test as passed"""
        print(f"{Colors.GREEN}✓ PASS:{Colors.NC} {message}")
        self.tests_passed += 1
    
    def fail_test(self, message: str):
        """Mark a test as failed"""
        print(f"{Colors.RED}✗ FAIL:{Colors.NC} {message}")
        self.tests_failed += 1
    
    def _print_test_header(self, test_name: str):
        """Print test header with number and name"""
        self.current_test_number += 1
        print(f"{Colors.YELLOW}Test {self.current_test_number} ({test_name}):{Colors.NC}")
    
    def test_init_basic(self):
        """Initialize server with basic config"""
        self._print_test_header("test_init_basic")
        result = self._run_docker_command(['init', '--server', 'vpn.example.com', 
                                          '--port', '7777', '--no-ca-pass'])
        
        if result.returncode == 0:
            if (os.path.exists(f"{self.test_data_dir}/control.conf") and 
                os.path.exists(f"{self.test_data_dir}/pki") and 
                os.path.exists(f"{self.test_data_dir}/openvpn")):
                self.pass_test("Server initialization")
            else:
                self.fail_test("Server initialization - missing files")
        else:
            self.fail_test("Server initialization failed")
    
    def test_verify_config(self):
        """Verify configuration file"""
        self._print_test_header("test_verify_config")
        config_path = f"{self.test_data_dir}/control.conf"
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            if config.get('server') == 'vpn.example.com' and config.get('port') == 7777:
                self.pass_test("Configuration file contains correct values")
            else:
                self.fail_test("Configuration file missing expected values")
        except Exception as e:
            self.fail_test(f"Configuration file verification failed: {e}")
    
    def test_update_config(self):
        """Update server configuration"""
        self._print_test_header("test_update_config")
        result = self._run_docker_command(['init', '--server', 'vpn.updated.com', 
                                          '--port', '8888', '--protocol', 'tcp', '--no-ca-pass'])
        
        if result.returncode == 0:
            try:
                with open(f"{self.test_data_dir}/control.conf", 'r') as f:
                    config = json.load(f)
                
                if (config.get('server') == 'vpn.updated.com' and 
                    config.get('port') == 8888 and 
                    config.get('protocol') == 'tcp'):
                    self.pass_test("Configuration update")
                else:
                    self.fail_test("Configuration update - values not updated")
            except Exception as e:
                self.fail_test(f"Configuration update failed: {e}")
        else:
            self.fail_test("Configuration update failed")
    
    def test_partial_config_update(self):
        """Update partial configuration"""
        self._print_test_header("test_partial_config_update")
        result = self._run_docker_command(['init', '--server', 'vpn.updated.com', 
                                          '--port', '9999', '--no-ca-pass'])
        
        if result.returncode == 0:
            try:
                with open(f"{self.test_data_dir}/control.conf", 'r') as f:
                    config = json.load(f)
                
                if (config.get('server') == 'vpn.updated.com' and 
                    config.get('port') == 9999 and 
                    config.get('protocol') == 'tcp'):  # Should be preserved from previous test
                    self.pass_test("Partial configuration update")
                else:
                    self.fail_test("Partial configuration update - values not preserved")
            except Exception as e:
                self.fail_test(f"Partial configuration update failed: {e}")
        else:
            self.fail_test("Partial configuration update failed")
    
    def test_new_client(self):
        """Create new client certificate"""
        self._print_test_header("test_new_client")
        result = self._run_docker_command(['new-client', 'testclient1', '--no-key-pass'])
        
        if result.returncode == 0:
            if (self._check_file_exists_in_container('pki/issued/testclient1.crt') and 
                self._check_file_exists_in_container('pki/private/testclient1.key')):
                self.pass_test("New client certificate creation")
            else:
                self.fail_test("New client certificate creation - missing files")
        else:
            self.fail_test("New client certificate creation failed")
    
    def test_second_client(self):
        """Create second client certificate"""
        self._print_test_header("test_second_client")
        result = self._run_docker_command(['new-client', 'testclient2', '--no-key-pass'])
        
        if result.returncode == 0:
            if self._check_file_exists_in_container('pki/issued/testclient2.crt'):
                self.pass_test("Second client certificate creation")
            else:
                self.fail_test("Second client certificate creation - missing files")
        else:
            self.fail_test("Second client certificate creation failed")
    
    def test_list_clients(self):
        """List clients"""
        self._print_test_header("test_list_clients")
        result = self._run_docker_command(['list-clients'], capture_output=True)
        
        if 'testclient1' in result.stdout and 'testclient2' in result.stdout:
            self.pass_test("List clients shows both clients")
        else:
            self.fail_test("List clients doesn't show expected clients")
    
    def test_show_client(self):
        """Show client certificate"""
        self._print_test_header("test_show_client")
        result = self._run_docker_command(['show-client', 'testclient1'], capture_output=True)
        
        if 'BEGIN CERTIFICATE' in result.stdout and 'END CERTIFICATE' in result.stdout:
            self.pass_test("Show client certificate")
        else:
            self.fail_test("Show client certificate - invalid output")
    
    def test_get_client_config(self):
        """Get client configuration"""
        self._print_test_header("test_get_client_config")
        result = self._run_docker_command(['get-client-config', 'testclient1'], capture_output=True)
        
        if ('client' in result.stdout and 
            'remote vpn.updated.com 9999' in result.stdout and 
            'BEGIN CERTIFICATE' in result.stdout and 
            'BEGIN PRIVATE KEY' in result.stdout):
            self.pass_test("Get client configuration")
        else:
            self.fail_test("Get client configuration - invalid output")
    
    def test_revoke_client(self):
        """Revoke client certificate"""
        self._print_test_header("test_revoke_client")
        result = self._run_docker_command(['revoke-client', 'testclient1'])
        
        if result.returncode == 0:
            list_result = self._run_docker_command(['list-clients'], capture_output=True)
            
            # Check if client is marked as revoked or not valid anymore
            if 'testclient1' in list_result.stdout and 'revoked' in list_result.stdout:
                self.pass_test("Client certificate revocation")
            elif 'testclient1' not in list_result.stdout or 'valid' not in list_result.stdout:
                self.pass_test("Client certificate revocation")
            else:
                self.fail_test("Client certificate revocation - client still marked as valid")
        else:
            self.fail_test("Client certificate revocation failed")
    
    def test_renew_client(self):
        """Renew client certificate"""
        self._print_test_header("test_renew_client")
        result = self._run_docker_command(['renew-client', 'testclient2'])
        
        if result.returncode == 0:
            if self._check_file_exists_in_container('pki/issued/testclient2.crt'):
                self.pass_test("Client certificate renewal")
            else:
                self.fail_test("Client certificate renewal - certificate missing")
        else:
            self.fail_test("Client certificate renewal failed")
    
    def test_ipv6_init(self):
        """Initialize with IPv6 support"""
        self._print_test_header("test_ipv6_init")
        # Clean up for fresh init
        self.cleanup()
        self.test_data_dir = tempfile.mkdtemp(prefix='openvpn-test-')
        
        result = self._run_docker_command(['init', '--server', 'vpn.ipv6.com', 
                                          '--port', '1194', '--ipv6', '--no-ca-pass'])
        
        if result.returncode == 0:
            try:
                with open(f"{self.test_data_dir}/control.conf", 'r') as f:
                    config = json.load(f)
                
                if config.get('ipv6') == True and 'network6' in config:
                    self.pass_test("IPv6 initialization")
                else:
                    self.fail_test("IPv6 initialization - config missing IPv6 settings")
            except Exception as e:
                self.fail_test(f"IPv6 initialization failed: {e}")
        else:
            self.fail_test("IPv6 initialization failed")
    
    def test_custom_network(self):
        """Initialize with custom network"""
        self._print_test_header("test_custom_network")
        self.cleanup()
        self.test_data_dir = tempfile.mkdtemp(prefix='openvpn-test-')
        
        result = self._run_docker_command(['init', '--server', 'vpn.custom.com', 
                                          '--port', '1194', '--network', '10.8.0.0/24', '--no-ca-pass'])
        
        if result.returncode == 0:
            try:
                with open(f"{self.test_data_dir}/control.conf", 'r') as f:
                    config = json.load(f)
                
                if config.get('network') == '10.8.0.0/24':
                    self.pass_test("Custom network configuration")
                else:
                    self.fail_test("Custom network configuration - network not set correctly")
            except Exception as e:
                self.fail_test(f"Custom network configuration failed: {e}")
        else:
            self.fail_test("Custom network configuration failed")
    
    def test_custom_dns(self):
        """Initialize with custom DNS servers"""
        self._print_test_header("test_custom_dns")
        self.cleanup()
        self.test_data_dir = tempfile.mkdtemp(prefix='openvpn-test-')
        
        result = self._run_docker_command(['init', '--server', 'vpn.dns.com', '--port', '1194', 
                                          '--no-ca-pass', '--dns-server', '1.1.1.1', 
                                          '--dns-server', '8.8.4.4'])
        
        if result.returncode == 0:
            try:
                with open(f"{self.test_data_dir}/control.conf", 'r') as f:
                    config = json.load(f)
                
                dns_servers = config.get('dns_servers', [])
                if '1.1.1.1' in dns_servers and '8.8.4.4' in dns_servers:
                    self.pass_test("Custom DNS servers configuration")
                else:
                    self.fail_test("Custom DNS servers configuration - DNS servers not set correctly")
            except Exception as e:
                self.fail_test(f"Custom DNS servers configuration failed: {e}")
        else:
            self.fail_test("Custom DNS servers configuration failed")
    
    def test_routes(self):
        """Initialize with additional routes"""
        self._print_test_header("test_routes")
        self.cleanup()
        self.test_data_dir = tempfile.mkdtemp(prefix='openvpn-test-')
        
        result = self._run_docker_command(['init', '--server', 'vpn.routes.com', '--port', '1194', 
                                          '--no-ca-pass', '--route', '192.168.1.0/24', 
                                          '--route', '192.168.2.0/24'])
        
        if result.returncode == 0:
            try:
                with open(f"{self.test_data_dir}/control.conf", 'r') as f:
                    config = json.load(f)
                
                routes = config.get('routes', [])
                if '192.168.1.0/24' in routes and '192.168.2.0/24' in routes:
                    self.pass_test("Additional routes configuration")
                else:
                    self.fail_test("Additional routes configuration - routes not set correctly")
            except Exception as e:
                self.fail_test(f"Additional routes configuration failed: {e}")
        else:
            self.fail_test("Additional routes configuration failed")
    
    def run_all_tests(self):
        """Run all integration tests"""
        print("=" * 41)
        print("OpenVPN Integration Tests")
        print("=" * 41)
        print(f"Image: {self.image_name}")
        print(f"Test data directory: {self.test_data_dir}")
        print(f"Verbose mode: {self.verbose}")
        print()
        
        # Run all tests
        tests = [
            self.test_init_basic,
            self.test_verify_config,
            self.test_update_config,
            self.test_partial_config_update,
            self.test_new_client,
            self.test_second_client,
            self.test_list_clients,
            self.test_show_client,
            self.test_get_client_config,
            self.test_revoke_client,
            self.test_renew_client,
            self.test_ipv6_init,
            self.test_custom_network,
            self.test_custom_dns,
            self.test_routes,
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                self.fail_test(f"{test.__name__} - Unexpected error: {e}")
        
        # Print summary
        print()
        print("=" * 41)
        print("Test Summary")
        print("=" * 41)
        print(f"Total tests: {self.tests_passed + self.tests_failed}")
        print(f"{Colors.GREEN}Passed: {self.tests_passed}{Colors.NC}")
        print(f"{Colors.RED}Failed: {self.tests_failed}{Colors.NC}")
        print("=" * 41)
        
        return self.tests_failed == 0


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Integration tests for docker-openvpn')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose output (shows docker commands and output)')
    parser.add_argument('--image', default=os.getenv('DOCKER_IMAGE', 'gerasiov/openvpn:test'),
                       help='Docker image name to test (default: gerasiov/openvpn:test)')
    
    args = parser.parse_args()
    
    tests = IntegrationTests(args.image, args.verbose)
    
    try:
        success = tests.run_all_tests()
        return 0 if success else 1
    finally:
        tests.cleanup()


if __name__ == '__main__':
    sys.exit(main())
