#!/bin/bash
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

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="${DOCKER_IMAGE:-gerasiov/openvpn:test}"
TEST_DATA_DIR="/tmp/openvpn-test-$$"
TESTS_PASSED=0
TESTS_FAILED=0

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning up test data...${NC}"
    rm -rf "$TEST_DATA_DIR"
}

# Setup trap for cleanup
trap cleanup EXIT

# Test result tracking
pass_test() {
    echo -e "${GREEN}✓ PASS:${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail_test() {
    echo -e "${RED}✗ FAIL:${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

# Docker run wrapper
run_openvpn() {
    docker run --rm -i -v "$TEST_DATA_DIR:/data" "$IMAGE_NAME" "$@"
}

# Initialize test environment
echo "========================================="
echo "OpenVPN Integration Tests"
echo "========================================="
echo "Image: $IMAGE_NAME"
echo "Test data directory: $TEST_DATA_DIR"
echo ""

# Create test data directory
mkdir -p "$TEST_DATA_DIR"

# Test 1: Initialize server with basic config
echo -e "${YELLOW}Test 1:${NC} Initialize server with basic config"
if run_openvpn init --server vpn.example.com --port 7777 --no-ca-pass > /dev/null 2>&1; then
    if [ -f "$TEST_DATA_DIR/control.conf" ] && [ -d "$TEST_DATA_DIR/pki" ] && [ -d "$TEST_DATA_DIR/openvpn" ]; then
        pass_test "Server initialization"
    else
        fail_test "Server initialization - missing files"
    fi
else
    fail_test "Server initialization failed"
fi

# Test 2: Verify config file contains expected values
echo -e "${YELLOW}Test 2:${NC} Verify configuration file"
if grep -q '"server": "vpn.example.com"' "$TEST_DATA_DIR/control.conf" && \
   grep -q '"port": 7777' "$TEST_DATA_DIR/control.conf"; then
    pass_test "Configuration file contains correct values"
else
    fail_test "Configuration file missing expected values"
fi

# Test 3: Update server config (full reconfiguration)
echo -e "${YELLOW}Test 3:${NC} Update server configuration"
if run_openvpn init --server vpn.updated.com --port 8888 --protocol tcp --no-ca-pass > /dev/null 2>&1; then
    if grep -q '"server": "vpn.updated.com"' "$TEST_DATA_DIR/control.conf" && \
       grep -q '"port": 8888' "$TEST_DATA_DIR/control.conf" && \
       grep -q '"protocol": "tcp"' "$TEST_DATA_DIR/control.conf"; then
        pass_test "Configuration update"
    else
        fail_test "Configuration update - values not updated"
    fi
else
    fail_test "Configuration update failed"
fi

# Test 4: Update partial config (only port)
echo -e "${YELLOW}Test 4:${NC} Update partial configuration"
if run_openvpn init --server vpn.updated.com --port 9999 --no-ca-pass > /dev/null 2>&1; then
    if grep -q '"server": "vpn.updated.com"' "$TEST_DATA_DIR/control.conf" && \
       grep -q '"port": 9999' "$TEST_DATA_DIR/control.conf" && \
       grep -q '"protocol": "tcp"' "$TEST_DATA_DIR/control.conf"; then
        pass_test "Partial configuration update"
    else
        fail_test "Partial configuration update - values not preserved"
    fi
else
    fail_test "Partial configuration update failed"
fi

# Test 5: Create a new client
echo -e "${YELLOW}Test 5:${NC} Create new client certificate"
if run_openvpn new-client testclient1 --no-key-pass > /dev/null 2>&1; then
    if [ -f "$TEST_DATA_DIR/pki/issued/testclient1.crt" ] && \
       [ -f "$TEST_DATA_DIR/pki/private/testclient1.key" ]; then
        pass_test "New client certificate creation"
    else
        fail_test "New client certificate creation - missing files"
    fi
else
    fail_test "New client certificate creation failed"
fi

# Test 6: Create another client
echo -e "${YELLOW}Test 6:${NC} Create second client certificate"
if run_openvpn new-client testclient2 --no-key-pass > /dev/null 2>&1; then
    if [ -f "$TEST_DATA_DIR/pki/issued/testclient2.crt" ]; then
        pass_test "Second client certificate creation"
    else
        fail_test "Second client certificate creation - missing files"
    fi
else
    fail_test "Second client certificate creation failed"
fi

# Test 7: List clients
echo -e "${YELLOW}Test 7:${NC} List clients"
output=$(run_openvpn list-clients 2>&1)
if echo "$output" | grep -q "testclient1" && echo "$output" | grep -q "testclient2"; then
    pass_test "List clients shows both clients"
else
    fail_test "List clients doesn't show expected clients"
fi

# Test 8: Show client certificate
echo -e "${YELLOW}Test 8:${NC} Show client certificate"
output=$(run_openvpn show-client testclient1 2>&1)
if echo "$output" | grep -q "BEGIN CERTIFICATE" && echo "$output" | grep -q "END CERTIFICATE"; then
    pass_test "Show client certificate"
else
    fail_test "Show client certificate - invalid output"
fi

# Test 9: Get client config
echo -e "${YELLOW}Test 9:${NC} Get client configuration"
output=$(run_openvpn get-client-config testclient1 2>&1)
if echo "$output" | grep -q "client" && \
   echo "$output" | grep -q "remote vpn.updated.com 9999" && \
   echo "$output" | grep -q "BEGIN CERTIFICATE" && \
   echo "$output" | grep -q "BEGIN PRIVATE KEY"; then
    pass_test "Get client configuration"
else
    fail_test "Get client configuration - invalid output"
fi

# Test 10: Revoke client
echo -e "${YELLOW}Test 10:${NC} Revoke client certificate"
if run_openvpn revoke-client testclient1 > /dev/null 2>&1; then
    output=$(run_openvpn list-clients 2>&1)
    if echo "$output" | grep -q "testclient1.*revoked"; then
        pass_test "Client certificate revocation"
    else
        fail_test "Client certificate revocation - client not marked as revoked"
    fi
else
    fail_test "Client certificate revocation failed"
fi

# Test 11: Renew client certificate
echo -e "${YELLOW}Test 11:${NC} Renew client certificate"
if run_openvpn renew-client testclient2 > /dev/null 2>&1; then
    if [ -f "$TEST_DATA_DIR/pki/issued/testclient2.crt" ]; then
        pass_test "Client certificate renewal"
    else
        fail_test "Client certificate renewal - certificate missing"
    fi
else
    fail_test "Client certificate renewal failed"
fi

# Test 12: Test init with IPv6
echo -e "${YELLOW}Test 12:${NC} Initialize with IPv6 support"
# Clean up for fresh init
rm -rf "$TEST_DATA_DIR"
mkdir -p "$TEST_DATA_DIR"

if run_openvpn init --server vpn.ipv6.com --port 1194 --ipv6 --no-ca-pass > /dev/null 2>&1; then
    if grep -q '"ipv6": true' "$TEST_DATA_DIR/control.conf" && \
       grep -q '"network6":' "$TEST_DATA_DIR/control.conf"; then
        pass_test "IPv6 initialization"
    else
        fail_test "IPv6 initialization - config missing IPv6 settings"
    fi
else
    fail_test "IPv6 initialization failed"
fi

# Test 13: Test init with custom network
echo -e "${YELLOW}Test 13:${NC} Initialize with custom network"
rm -rf "$TEST_DATA_DIR"
mkdir -p "$TEST_DATA_DIR"

if run_openvpn init --server vpn.custom.com --port 1194 --network 10.8.0.0/24 --no-ca-pass > /dev/null 2>&1; then
    if grep -q '"network": "10.8.0.0/24"' "$TEST_DATA_DIR/control.conf"; then
        pass_test "Custom network configuration"
    else
        fail_test "Custom network configuration - network not set correctly"
    fi
else
    fail_test "Custom network configuration failed"
fi

# Test 14: Test init with DNS servers
echo -e "${YELLOW}Test 14:${NC} Initialize with custom DNS servers"
rm -rf "$TEST_DATA_DIR"
mkdir -p "$TEST_DATA_DIR"

if run_openvpn init --server vpn.dns.com --port 1194 --no-ca-pass --dns-server 1.1.1.1 --dns-server 8.8.4.4 > /dev/null 2>&1; then
    if grep -q '"1.1.1.1"' "$TEST_DATA_DIR/control.conf" && \
       grep -q '"8.8.4.4"' "$TEST_DATA_DIR/control.conf"; then
        pass_test "Custom DNS servers configuration"
    else
        fail_test "Custom DNS servers configuration - DNS servers not set correctly"
    fi
else
    fail_test "Custom DNS servers configuration failed"
fi

# Test 15: Test init with routes
echo -e "${YELLOW}Test 15:${NC} Initialize with additional routes"
rm -rf "$TEST_DATA_DIR"
mkdir -p "$TEST_DATA_DIR"

if run_openvpn init --server vpn.routes.com --port 1194 --no-ca-pass --route 192.168.1.0/24 --route 192.168.2.0/24 > /dev/null 2>&1; then
    if grep -q '"192.168.1.0/24"' "$TEST_DATA_DIR/control.conf" && \
       grep -q '"192.168.2.0/24"' "$TEST_DATA_DIR/control.conf"; then
        pass_test "Additional routes configuration"
    else
        fail_test "Additional routes configuration - routes not set correctly"
    fi
else
    fail_test "Additional routes configuration failed"
fi

# Print summary
echo ""
echo "========================================="
echo "Test Summary"
echo "========================================="
echo -e "Total tests: $((TESTS_PASSED + TESTS_FAILED))"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo "========================================="

# Exit with appropriate code
if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
