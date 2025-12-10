package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	serverEasyRsaID = "_server"
	// Device numbers for /dev/net/tun
	tunDeviceMajor  = 10
	tunDeviceMinor  = 200
)

var (
	dataDir     string
	openvpnDir  string
	easyRsaPKI  string
	logger      *log.Logger
	verboseMode bool
)

// Config represents the configuration for the OpenVPN server
type Config struct {
	Server              *string  `json:"server"`
	IPv6                bool     `json:"ipv6"`
	Network             string   `json:"network"`
	Network6            *string  `json:"network6"`
	Routes              []string `json:"routes"`
	Route6s             []string `json:"route6s"`
	Protocol            string   `json:"protocol"`
	Port                int      `json:"port"`
	Device              string   `json:"device"`
	Interface           string   `json:"interface"`
	NAT                 bool     `json:"nat"`
	NAT6                *bool    `json:"nat6"`
	DNSServers          []string `json:"dns_servers"`
	ClientToClient      bool     `json:"client_to_client"`
	DuplicateCN         bool     `json:"duplicate_cn"`
	CompLZO             bool     `json:"comp_lzo"`
	DefaultRoute        bool     `json:"default_route"`
	DefaultRoute6       *bool    `json:"default_route6"`
	BlockOutsideDNS     bool     `json:"block_outside_dns"`
	RestartInterval     int      `json:"restart_interval"`
	ExtraServerConfigs  []string `json:"extra_server_configs"`
	ExtraClientConfigs  []string `json:"extra_client_configs"`
}

// NewConfig creates a new Config with default values
func NewConfig() *Config {
	return &Config{
		Network:         "172.30.0.0/16",
		Routes:          []string{},
		Route6s:         []string{},
		Protocol:        "udp",
		Port:            1194,
		Device:          "tun",
		Interface:       "eth0",
		NAT:             true,
		DNSServers:      []string{"8.8.8.8", "1.1.1.1"},
		DefaultRoute:    true,
		BlockOutsideDNS: true,
		RestartInterval: 30,
		ExtraServerConfigs: []string{},
		ExtraClientConfigs: []string{},
	}
}

func init() {
	dataDir = os.Getenv("OVPN_WORKDIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	openvpnDir = filepath.Join(dataDir, "openvpn")
	easyRsaPKI = filepath.Join(dataDir, "pki")
	logger = log.New(os.Stderr, "", 0)
}

func logInfo(format string, v ...interface{}) {
	logger.Printf(format, v...)
}

func logDebug(format string, v ...interface{}) {
	if verboseMode {
		logger.Printf("DEBUG: "+format, v...)
	}
}

func logError(format string, v ...interface{}) {
	logger.Printf("ERROR: "+format, v...)
}

func logWarning(format string, v ...interface{}) {
	logger.Printf("WARNING: "+format, v...)
}

// parseCIDR parses a CIDR string and returns network and netmask
func parseCIDR(cidr string) (string, string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}
	return ipnet.IP.String(), net.IP(ipnet.Mask).String(), nil
}

// normalizeAddress normalizes an address (CIDR or plain IP)
func normalizeAddress(address string) string {
	if strings.Contains(address, "/") {
		network, netmask, err := parseCIDR(address)
		if err != nil {
			return address
		}
		return network + " " + netmask
	}
	return address
}

// generateULANetwork generates a random ULA IPv6 network
func generateULANetwork() (string, error) {
	// ULA prefix is fd00::/8
	// We want to generate a /64 network
	// Random 56 bits between fd00::/8 prefix and /64 subnet
	randomBits := 56

	// Generate random bytes
	max := new(big.Int).Lsh(big.NewInt(1), uint(randomBits))
	randomNum, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	// Shift left by 64 bits to make room for host part
	randomNum.Lsh(randomNum, 64)

	// Add fd00:: prefix (0xfd00 << 112)
	prefix := new(big.Int).Lsh(big.NewInt(0xfd00), 112)
	randomNum.Add(randomNum, prefix)

	// Convert to IPv6 address
	bytes := randomNum.Bytes()
	// Pad to 16 bytes if necessary
	if len(bytes) < 16 {
		paddedBytes := make([]byte, 16)
		copy(paddedBytes[16-len(bytes):], bytes)
		bytes = paddedBytes
	}

	ip := net.IP(bytes)
	return ip.String() + "/64", nil
}

// LoadConfig loads configuration from file
func (c *Config) LoadConfig(filename string) error {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, c)
}

// SaveConfig saves configuration to file
func (c *Config) SaveConfig(filename string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// UpdateFromEnv updates config from environment variables
func (c *Config) UpdateFromEnv() {
	if v := os.Getenv("OVPN_SERVER"); v != "" {
		c.Server = &v
	}
	if v := os.Getenv("OVPN_IPV6"); v != "" {
		c.IPv6 = parseBool(v)
	}
	if v := os.Getenv("OVPN_NETWORK"); v != "" {
		c.Network = v
	}
	if v := os.Getenv("OVPN_NETWORK6"); v != "" {
		c.Network6 = &v
	}
	if v := os.Getenv("OVPN_ROUTES"); v != "" {
		c.Routes = strings.Split(v, ",")
	}
	if v := os.Getenv("OVPN_ROUTE6S"); v != "" {
		c.Route6s = strings.Split(v, ",")
	}
	if v := os.Getenv("OVPN_PROTOCOL"); v != "" {
		c.Protocol = v
	}
	if v := os.Getenv("OVPN_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			c.Port = port
		}
	}
	if v := os.Getenv("OVPN_DEVICE"); v != "" {
		c.Device = v
	}
	if v := os.Getenv("OVPN_INTERFACE"); v != "" {
		c.Interface = v
	}
	if v := os.Getenv("OVPN_NAT"); v != "" {
		c.NAT = parseBool(v)
	}
	if v := os.Getenv("OVPN_NAT6"); v != "" {
		b := parseBool(v)
		c.NAT6 = &b
	}
	if v := os.Getenv("OVPN_DNS_SERVERS"); v != "" {
		c.DNSServers = strings.Split(v, ",")
	}
	if v := os.Getenv("OVPN_CLIENT_TO_CLIENT"); v != "" {
		c.ClientToClient = parseBool(v)
	}
	if v := os.Getenv("OVPN_DUPLICATE_CN"); v != "" {
		c.DuplicateCN = parseBool(v)
	}
	if v := os.Getenv("OVPN_COMP_LZO"); v != "" {
		c.CompLZO = parseBool(v)
	}
	if v := os.Getenv("OVPN_DEFAULT_ROUTE"); v != "" {
		c.DefaultRoute = parseBool(v)
	}
	if v := os.Getenv("OVPN_DEFAULT_ROUTE6"); v != "" {
		b := parseBool(v)
		c.DefaultRoute6 = &b
	}
	if v := os.Getenv("OVPN_BLOCK_OUTSIDE_DNS"); v != "" {
		c.BlockOutsideDNS = parseBool(v)
	}
	if v := os.Getenv("OVPN_RESTART_INTERVAL"); v != "" {
		if interval, err := strconv.Atoi(v); err == nil {
			c.RestartInterval = interval
		}
	}
	if v := os.Getenv("OVPN_EXTRA_SERVER_CONFIGS"); v != "" {
		c.ExtraServerConfigs = strings.Split(v, ",")
	}
	if v := os.Getenv("OVPN_EXTRA_CLIENT_CONFIGS"); v != "" {
		c.ExtraClientConfigs = strings.Split(v, ",")
	}
}

func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "yes" || s == "1"
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server == nil || *c.Server == "" {
		return fmt.Errorf("server's hostname not set")
	}
	if !strings.Contains(c.Network, "/") {
		return fmt.Errorf("network should be in CIDR format")
	}
	if c.IPv6 {
		if c.Network6 == nil || !strings.Contains(*c.Network6, "/") {
			return fmt.Errorf("IPv6 network should be in CIDR format")
		}
	}
	return nil
}

// FinalizeConfig sets derived configuration values
func (c *Config) FinalizeConfig() error {
	if c.IPv6 {
		if c.Network6 == nil {
			network, err := generateULANetwork()
			if err != nil {
				return err
			}
			c.Network6 = &network
		}
		if c.DefaultRoute6 == nil {
			c.DefaultRoute6 = &c.DefaultRoute
		}
		if c.NAT6 == nil {
			c.NAT6 = &c.NAT
		}
	}
	return nil
}

// runCommand runs a command and returns error if it fails
func runCommand(name string, args ...string) error {
	logDebug("Running command: %s %s", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runCommandOutput runs a command and returns its output
func runCommandOutput(name string, args ...string) (string, error) {
	logDebug("Running command: %s %s", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// getEasyRSACmd returns the easyrsa command with standard options
func getEasyRSACmd(args ...string) []string {
	base := []string{"easyrsa", fmt.Sprintf("--pki=%s", easyRsaPKI), "--batch", "--silent"}
	return append(base, args...)
}

// initEasyRSA initializes the EasyRSA PKI
func initEasyRSA(config *Config, caPass bool) error {
	logInfo("Initializing EasyRSA.")

	var noPass []string
	serverCertValidity := config.RestartInterval * 2

	if caPass {
		if _, err := os.Stat(easyRsaPKI); os.IsNotExist(err) {
			logInfo("CA key will be password protected, do not forget it.")
			logInfo("Remember to manually renew server certificate when it expires.")
		}
		serverCertValidity = 365 * 3
	} else {
		noPass = []string{"--no-pass"}
	}

	// Initialize PKI
	if _, err := os.Stat(easyRsaPKI); os.IsNotExist(err) {
		cmd := getEasyRSACmd("init-pki")
		if err := runCommand(cmd[0], cmd[1:]...); err != nil {
			return err
		}
		if err := os.Chmod(easyRsaPKI, 0711); err != nil {
			return err
		}
	}

	// Build CA
	caFile := filepath.Join(easyRsaPKI, "ca.crt")
	if _, err := os.Stat(caFile); os.IsNotExist(err) {
		cmd := getEasyRSACmd(append(noPass, "build-ca")...)
		if err := runCommand(cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}

	// Generate DH parameters
	dhFile := filepath.Join(easyRsaPKI, "dh.pem")
	if _, err := os.Stat(dhFile); os.IsNotExist(err) {
		cmd := getEasyRSACmd("gen-dh")
		if err := runCommand(cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}

	// Generate server request
	reqFile := filepath.Join(easyRsaPKI, "reqs", serverEasyRsaID+".req")
	if _, err := os.Stat(reqFile); os.IsNotExist(err) {
		cmd := getEasyRSACmd(fmt.Sprintf("--req-cn=%s", *config.Server), "gen-req", serverEasyRsaID, "nopass")
		if err := runCommand(cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}

	// Sign server certificate
	certFile := filepath.Join(easyRsaPKI, "issued", serverEasyRsaID+".crt")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		cmd := getEasyRSACmd(fmt.Sprintf("--days=%d", serverCertValidity), "sign-req", "server", serverEasyRsaID)
		if err := runCommand(cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}

	return updateCRL()
}

// initOpenVPN initializes the OpenVPN server configuration
func initOpenVPN(config *Config) error {
	logInfo("Initializing OpenVPN server configuration.")

	if _, err := os.Stat(openvpnDir); os.IsNotExist(err) {
		logInfo("Initializing OpenVPN directory %s.", openvpnDir)
		if err := os.MkdirAll(openvpnDir, 0755); err != nil {
			return err
		}
	} else {
		logWarning("OpenVPN directory %s already exists, overwriting configuration...", openvpnDir)
		logWarning("Old client configuration could became invalid, consider regenerating them.")
	}

	// Generate ta.key
	taFile := filepath.Join(openvpnDir, "ta.key")
	if _, err := os.Stat(taFile); os.IsNotExist(err) {
		cmd := exec.Command("openvpn", "--genkey", "secret", "ta.key")
		cmd.Dir = openvpnDir
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	logInfo("Creating server configuration.")

	configOptions := []string{
		fmt.Sprintf("server %s", normalizeAddress(config.Network)),
		"verb 3",
		fmt.Sprintf("proto %s", config.Protocol),
		"port 1194",
		fmt.Sprintf("dev %s0", config.Device),
		"topology subnet",
		"keepalive 10 60",
		"persist-key",
		"persist-tun",
		fmt.Sprintf("ca %s/ca.crt", easyRsaPKI),
		fmt.Sprintf("key %s/private/%s.key", easyRsaPKI, serverEasyRsaID),
		fmt.Sprintf("cert %s/issued/%s.crt", easyRsaPKI, serverEasyRsaID),
		fmt.Sprintf("dh %s/dh.pem", easyRsaPKI),
		fmt.Sprintf("tls-auth %s/ta.key 0", openvpnDir),
		fmt.Sprintf("crl-verify %s/crl.pem", easyRsaPKI),
		"status /tmp/openvpn-status.log",
		"user nobody",
		"group nogroup",
	}

	if config.Network6 != nil {
		configOptions = append(configOptions, fmt.Sprintf("server-ipv6 %s", *config.Network6))
	}

	for _, subnet := range config.Routes {
		parts := strings.Fields(subnet)
		if len(parts) > 0 {
			normalized := normalizeAddress(parts[0])
			if len(parts) > 1 {
				normalized = normalized + " " + strings.Join(parts[1:], " ")
			}
			configOptions = append(configOptions, fmt.Sprintf("push \"route %s\"", normalized))
		}
	}

	for _, subnet := range config.Route6s {
		configOptions = append(configOptions, fmt.Sprintf("push \"route-ipv6 %s\"", subnet))
	}

	for _, dnsServer := range config.DNSServers {
		configOptions = append(configOptions, fmt.Sprintf("push \"dhcp-option DNS %s\"", dnsServer))
	}

	if config.ClientToClient {
		configOptions = append(configOptions, "client-to-client")
	}

	if config.DuplicateCN {
		configOptions = append(configOptions, "duplicate-cn")
	}

	if config.CompLZO {
		logWarning("LZO compression is deprecated and not recommended.")
		configOptions = append(configOptions, "comp-lzo yes")
		configOptions = append(configOptions, "push \"comp-lzo yes\"")
	}

	if config.BlockOutsideDNS {
		configOptions = append(configOptions, "push \"block-outside-dns\"")
	}

	configOptions = append(configOptions, config.ExtraServerConfigs...)

	// Write configuration file
	serverConfFile := filepath.Join(openvpnDir, "server.conf")
	f, err := os.Create(serverConfFile)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, line := range configOptions {
		if _, err := f.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	return nil
}

// updateCRL updates the certificate revocation list
func updateCRL() error {
	logInfo("Updating CRL file.")

	expirationDate, err := getCertExpiration(serverEasyRsaID)
	if err != nil {
		return err
	}

	days := int(time.Until(expirationDate).Hours()/24) + 1

	cmd := getEasyRSACmd(fmt.Sprintf("--days=%d", days), "gen-crl")
	if err := runCommand(cmd[0], cmd[1:]...); err != nil {
		return err
	}

	crlFile := filepath.Join(easyRsaPKI, "crl.pem")
	return os.Chmod(crlFile, 0644)
}

// getCertExpiration returns the expiration date of a certificate
func getCertExpiration(name string) (time.Time, error) {
	certFile := filepath.Join(easyRsaPKI, "issued", name+".crt")
	output, err := runCommandOutput("openssl", "x509", "-noout", "-enddate", "-dateopt", "iso_8601", "-in", certFile)
	if err != nil {
		return time.Time{}, err
	}

	// Parse output like "notAfter=2025-12-10T20:22:57Z" or "notAfter=2025-12-10 20:22:57Z"
	parts := strings.Split(strings.TrimSpace(output), "=")
	if len(parts) != 2 {
		return time.Time{}, fmt.Errorf("unexpected openssl output: %s", output)
	}

	dateStr := strings.TrimSpace(parts[1])
	
	// OpenSSL's iso_8601 format can output either with 'T' or space separator
	// Replace space with 'T' to ensure RFC3339 compliance
	dateStr = strings.Replace(dateStr, " ", "T", 1)
	
	return time.Parse(time.RFC3339, dateStr)
}

// checkCertValidity checks if a certificate is valid
func checkCertValidity(name string, purpose string) (string, *time.Time, error) {
	certFile := filepath.Join(easyRsaPKI, "issued", name+".crt")
	caFile := filepath.Join(easyRsaPKI, "ca.crt")
	crlFile := filepath.Join(easyRsaPKI, "crl.pem")

	cmd := exec.Command("openssl", "verify", "-crl_check_all", "-purpose", purpose, "-CAfile", caFile, "-CRLfile", crlFile, certFile)
	output, err := cmd.CombinedOutput()

	if err == nil {
		expiration, err := getCertExpiration(name)
		if err != nil {
			return "valid", nil, err
		}
		return "valid", &expiration, nil
	}

	// Parse error
	outputStr := string(output)
	for _, line := range strings.Split(outputStr, "\n") {
		if strings.HasPrefix(line, "error") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				errorCode := fields[1]
				switch errorCode {
				case "10":
					expiration, _ := getCertExpiration(name)
					return "expired", &expiration, nil
				case "23":
					return "revoked", nil, nil
				case "26":
					return "not sslclient certificate", nil, nil
				}
			}
		}
	}

	return "unknown error", nil, nil
}

// renewCert renews a certificate
func renewCert(name string, days *int) error {
	renewedCertFile := filepath.Join(easyRsaPKI, "renewed", "issued", name+".crt")
	if _, err := os.Stat(renewedCertFile); !os.IsNotExist(err) {
		logWarning("Renewed certificate for %s already exists, removing it.", name)
		cmd := getEasyRSACmd("revoke-renewed", name)
		if err := runCommand(cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}

	var cmd []string
	if days != nil {
		cmd = getEasyRSACmd(fmt.Sprintf("--days=%d", *days+1), "renew", name)
	} else {
		cmd = getEasyRSACmd("renew", name)
	}
	if err := runCommand(cmd[0], cmd[1:]...); err != nil {
		return err
	}

	cmd = getEasyRSACmd("revoke-renewed", name)
	return runCommand(cmd[0], cmd[1:]...)
}

// renewServerCert renews the server certificate if needed
func renewServerCert(config *Config, allowEncrypted bool, days *int) error {
	validity, date, err := checkCertValidity(serverEasyRsaID, "sslserver")
	if err != nil {
		return err
	}

	// Check if CA key is encrypted
	caKeyFile := filepath.Join(easyRsaPKI, "private", "ca.key")
	caKeyData, err := os.ReadFile(caKeyFile)
	if err != nil {
		return err
	}
	caKeyEncrypted := strings.Contains(string(caKeyData), "ENCRYPTED")

	needsRenewal := days != nil || validity != "valid" || date == nil ||
		time.Until(*date).Hours()/24 < float64(config.RestartInterval*2)

	if needsRenewal {
		if caKeyEncrypted && !allowEncrypted {
			logError("Server certificate needs renewal, but CA key is password protected.")
			logError("Run the `renew-server` command to renew the certificate.")
			os.Exit(1)
		}
		logInfo("Renewing server certificate.")

		renewDays := config.RestartInterval * 3
		if days != nil {
			renewDays = *days
		}
		if err := renewCert(serverEasyRsaID, &renewDays); err != nil {
			return err
		}
		return updateCRL()
	}

	return nil
}

// checkSysctl checks a sysctl value
func checkSysctl(name, sysctl, expectedValue string, isError bool) error {
	path := filepath.Join("/proc/sys", strings.ReplaceAll(sysctl, ".", "/"))
	data, err := os.ReadFile(path)
	if err != nil {
		msg := fmt.Sprintf("Failed to read %s: %v", sysctl, err)
		if isError {
			logError(msg)
			return fmt.Errorf("%s", msg)
		}
		logWarning(msg)
		return nil
	}

	currentValue := strings.TrimSpace(string(data))
	if currentValue != expectedValue {
		msg := fmt.Sprintf("%s is set to %s. Set it with sysctl \"%s=%s\"", name, currentValue, sysctl, expectedValue)
		if isError {
			logError(msg)
			return fmt.Errorf("%s", msg)
		}
		logWarning(msg)
	}
	return nil
}

// cmdInit handles the init command
func cmdInit(config *Config, caPass bool) error {
	if caPass && !isatty(os.Stdin) {
		logError("CA password required, but stdin is not a tty.")
		return fmt.Errorf("CA password required but stdin is not a tty")
	}

	if err := initEasyRSA(config, caPass); err != nil {
		return err
	}
	if err := initOpenVPN(config); err != nil {
		return err
	}

	logInfo("Initialization complete.")
	return nil
}

// cmdStart handles the start command
func cmdStart(config *Config, readonly bool) error {
	logInfo("Preparing environment...")

	// Create /dev/net/tun
	if err := os.MkdirAll("/dev/net", 0755); err != nil && !os.IsExist(err) {
		return err
	}

	if _, err := os.Stat("/dev/net/tun"); os.IsNotExist(err) {
		dev := int(makedev(tunDeviceMajor, tunDeviceMinor))
		if err := syscall.Mknod("/dev/net/tun", syscall.S_IFCHR|0666, dev); err != nil {
			return err
		}
	}

	if !readonly {
		if err := renewServerCert(config, false, nil); err != nil {
			return err
		}
	}

	if err := checkSysctl("IPv4 forwarding", "net.ipv4.ip_forward", "1", false); err != nil {
		return err
	}

	if config.IPv6 {
		if err := checkSysctl("IPv6 disable", "net.ipv6.conf.default.disable_ipv6", "0", true); err != nil {
			return err
		}
		if err := checkSysctl("IPv6 disable", fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6", config.Interface), "0", false); err != nil {
			return err
		}
		if err := checkSysctl("IPv6 forwarding", "net.ipv6.conf.all.forwarding", "1", false); err != nil {
			return err
		}
	}

	if config.NAT {
		// Remove existing rule (ignore errors)
		_ = runCommand("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", config.Network, "-o", config.Interface, "-j", "MASQUERADE")
		// Add new rule
		if err := runCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", config.Network, "-o", config.Interface, "-j", "MASQUERADE"); err != nil {
			return err
		}
	}

	if config.IPv6 && config.NAT6 != nil && *config.NAT6 {
		// Remove existing rule (ignore errors)
		_ = runCommand("ip6tables", "-t", "nat", "-D", "POSTROUTING", "-s", *config.Network6, "-o", config.Interface, "-j", "MASQUERADE")
		// Add new rule
		if err := runCommand("ip6tables", "-t", "nat", "-A", "POSTROUTING", "-s", *config.Network6, "-o", config.Interface, "-j", "MASQUERADE"); err != nil {
			return err
		}
	}

	logInfo("Starting OpenVPN server:")

	// Calculate timeout in seconds
	timeout := config.RestartInterval * 24 * 60 * 60

	// Get the path to the current executable
	executable, err := os.Executable()
	if err != nil {
		executable = os.Args[0]
	}

	// Execute shell command with timeout and restart
	cmd := fmt.Sprintf("timeout %d openvpn --config %s/server.conf; exec %s start",
		timeout, openvpnDir, executable)

	return syscall.Exec("/bin/sh", []string{"/bin/sh", "-c", cmd}, os.Environ())
}

// cmdNewClient handles the new-client command
func cmdNewClient(config *Config, clientName string, keyPass bool) error {
	if keyPass && !isatty(os.Stdin) {
		logError("Key password required, but stdin is not a tty.")
		return fmt.Errorf("key password required but stdin is not a tty")
	}

	logInfo("Creating new client %s", clientName)

	// Generate client request
	reqFile := filepath.Join(easyRsaPKI, "reqs", clientName+".req")
	if _, err := os.Stat(reqFile); os.IsNotExist(err) {
		var cmd []string
		if keyPass {
			cmd = getEasyRSACmd(fmt.Sprintf("--req-cn=%s", clientName), "gen-req", clientName)
		} else {
			cmd = getEasyRSACmd(fmt.Sprintf("--req-cn=%s", clientName), "gen-req", clientName, "nopass")
		}
		if err := runCommand(cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}

	// Sign client certificate
	certFile := filepath.Join(easyRsaPKI, "issued", clientName+".crt")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		cmd := getEasyRSACmd("sign-req", "client", clientName)
		if err := runCommand(cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}

	return nil
}

// cmdRevokeClient handles the revoke-client command
func cmdRevokeClient(config *Config, clientName string) error {
	logInfo("Revoking client %s.", clientName)

	certFile := filepath.Join(easyRsaPKI, "issued", clientName+".crt")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		logError("Client %s does not exist", clientName)
		return fmt.Errorf("client does not exist")
	}

	cmd := getEasyRSACmd("revoke", clientName)
	if err := runCommand(cmd[0], cmd[1:]...); err != nil {
		return err
	}

	return updateCRL()
}

// cmdRenewClient handles the renew-client command
func cmdRenewClient(config *Config, clientName string) error {
	logInfo("Renewing client %s.", clientName)

	certFile := filepath.Join(easyRsaPKI, "issued", clientName+".crt")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		logError("Client %s does not exist", clientName)
		return fmt.Errorf("client does not exist")
	}

	if err := renewCert(clientName, nil); err != nil {
		return err
	}

	return updateCRL()
}

// cmdRenewServer handles the renew-server command
func cmdRenewServer(config *Config, days int) error {
	return renewServerCert(config, true, &days)
}

// cmdListClients handles the list-clients command
func cmdListClients(config *Config) error {
	logInfo("Listing clients:")

	issuedDir := filepath.Join(easyRsaPKI, "issued")
	files, err := os.ReadDir(issuedDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".crt") {
			clientName := strings.TrimSuffix(file.Name(), ".crt")
			if clientName == serverEasyRsaID {
				continue
			}

			validity, expirationDate, _ := checkCertValidity(clientName, "sslclient")
			if validity == "valid" {
				fmt.Printf("%s, valid till %s\n", clientName, expirationDate.Format(time.RFC3339))
			} else if validity == "expired" {
				fmt.Printf("%s, expired on %s\n", clientName, expirationDate.Format(time.RFC3339))
			} else {
				fmt.Printf("%s, %s\n", clientName, validity)
			}
		}
	}

	return nil
}

// cmdShowClient handles the show-client command
func cmdShowClient(config *Config, clientName string) error {
	logInfo("Showing client %s:", clientName)

	certFile := filepath.Join(easyRsaPKI, "issued", clientName+".crt")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		logError("Client %s does not exist", clientName)
		return fmt.Errorf("client does not exist")
	}

	data, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}

	fmt.Print(string(data))
	return nil
}

// cmdGetClientConfig handles the get-client-config command
func cmdGetClientConfig(config *Config, clientName string) error {
	logInfo("Getting client config for %s:", clientName)

	certFile := filepath.Join(easyRsaPKI, "issued", clientName+".crt")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		logError("Client %s does not exist", clientName)
		return fmt.Errorf("client does not exist")
	}

	configOptions := []string{
		"client",
		"nobind",
		fmt.Sprintf("dev %s", config.Device),
		fmt.Sprintf("remote %s %d %s", *config.Server, config.Port, strings.TrimSuffix(config.Protocol, "6")),
		"remote-cert-tls server",
		"key-direction 1",
	}

	configOptions = append(configOptions, config.ExtraClientConfigs...)

	// Build redirect-gateway option
	var redirectGateway []string
	if config.DefaultRoute {
		redirectGateway = append(redirectGateway, "def1")
	}
	if config.DefaultRoute6 != nil && *config.DefaultRoute6 {
		redirectGateway = append(redirectGateway, "ipv6")
	}
	if len(redirectGateway) > 0 && !config.DefaultRoute {
		redirectGateway = append(redirectGateway, "!ipv4")
	}
	if len(redirectGateway) > 0 {
		configOptions = append(configOptions, fmt.Sprintf("redirect-gateway %s", strings.Join(redirectGateway, " ")))
	}

	// Output configuration
	for _, line := range configOptions {
		fmt.Println(line)
	}

	// Output embedded files
	files := map[string]string{
		"key":      filepath.Join(easyRsaPKI, "private", clientName+".key"),
		"cert":     filepath.Join(easyRsaPKI, "issued", clientName+".crt"),
		"ca":       filepath.Join(easyRsaPKI, "ca.crt"),
		"tls-auth": filepath.Join(openvpnDir, "ta.key"),
	}

	for key, path := range files {
		fmt.Printf("<%s>\n", key)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fmt.Print(string(data))
		fmt.Printf("</%s>\n", key)
	}

	return nil
}

// isatty checks if the file is a terminal
// Uses a direct syscall to check terminal status
func isatty(f *os.File) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&termios)), 0, 0, 0)
	return err == 0
}

// makedev creates a device number from major and minor numbers
// This follows the Linux makedev implementation:
// - Lower 8 bits (0xff) are the minor device number
// - Next 12 bits (0xfff00) are also part of minor (shifted left by 12)
// - Bits 8-15 are the major device number
func makedev(major, minor uint32) int {
	return int((major << 8) | (minor & 0xff) | ((minor & 0xfff00) << 12))
}

func main() {
	var (
		verbose bool
	)

	// Define flags
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <command> [command options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nGlobal options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nCommands:\n")
		fmt.Fprintf(os.Stderr, "  init                Initialize OpenVPN server\n")
		fmt.Fprintf(os.Stderr, "  start               Start OpenVPN server\n")
		fmt.Fprintf(os.Stderr, "  renew-server        Renew server certificate\n")
		fmt.Fprintf(os.Stderr, "  new-client          Create new client certificate\n")
		fmt.Fprintf(os.Stderr, "  revoke-client       Revoke client certificate\n")
		fmt.Fprintf(os.Stderr, "  renew-client        Renew client certificate\n")
		fmt.Fprintf(os.Stderr, "  list-clients        List clients\n")
		fmt.Fprintf(os.Stderr, "  show-client         Show client certificate\n")
		fmt.Fprintf(os.Stderr, "  get-client-config   Get client config\n")
	}

	flag.Parse()
	verboseMode = verbose

	if verboseMode {
		logger.SetFlags(log.LstdFlags)
	}

	logInfo("Starting docker-openvpn script")

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	command := args[0]
	logDebug("Action: %s", command)

	// Check data directory
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		logError("Data directory %s does not exist, may be missing volume mount.", dataDir)
		os.Exit(1)
	}

	// Load config
	config := NewConfig()
	configFile := filepath.Join(dataDir, "control.conf")
	if err := config.LoadConfig(configFile); err != nil {
		logError("Failed to load config: %v", err)
		os.Exit(1)
	}

	// Update from environment
	config.UpdateFromEnv()

	// Handle commands
	var err error

	switch command {
	case "init":
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		var (
			caPass            bool
			noCaPass          bool
			server            string
			protocol          string
			port              int
			restartInterval   int
			ipv6              bool
			noIPv6            bool
			network           string
			network6          string
			device            string
			iface             string
			nat               bool
			noNAT             bool
			nat6              bool
			noNAT6            bool
			compLZO           bool
			noCompLZO         bool
			duplicateCN       bool
			noDuplicateCN     bool
			blockOutsideDNS   bool
			noBlockOutsideDNS bool
			clientToClient    bool
			noClientToClient  bool
			defaultRoute      bool
			noDefaultRoute    bool
			defaultRoute6     bool
			noDefaultRoute6   bool
		)

		var (
			dnsServers         arrayFlags
			noDNSServers       bool
			routes             arrayFlags
			noRoutes           bool
			route6s            arrayFlags
			noRoute6s          bool
			extraServerConfigs arrayFlags
			noExtraServerConfigs bool
			extraClientConfigs arrayFlags
			noExtraClientConfigs bool
		)

		fs.BoolVar(&caPass, "ca-pass", false, "Require password for CA key")
		fs.BoolVar(&noCaPass, "no-ca-pass", false, "Disable ca-pass (default)")
		fs.StringVar(&server, "server", "", "Server name")
		fs.StringVar(&protocol, "protocol", config.Protocol, "Server protocol")
		fs.IntVar(&port, "port", config.Port, "Server port")
		fs.IntVar(&restartInterval, "restart-interval", config.RestartInterval, "Server restart interval in days")
		fs.BoolVar(&ipv6, "ipv6", false, "Enable IPv6 support")
		fs.BoolVar(&noIPv6, "no-ipv6", false, "Disable ipv6 (default)")
		fs.StringVar(&network, "network", config.Network, "Network CIDR to use")
		fs.StringVar(&network6, "network6", "", "IPv6 network CIDR to use")
		fs.StringVar(&device, "device", config.Device, "Device to use")
		fs.StringVar(&iface, "interface", config.Interface, "Interface to use")
		fs.BoolVar(&nat, "nat", false, "NAT traffic from clients")
		fs.BoolVar(&noNAT, "no-nat", false, "Disable nat")
		fs.BoolVar(&nat6, "nat6", false, "NAT IPv6 traffic")
		fs.BoolVar(&noNAT6, "no-nat6", false, "Disable nat6")
		fs.BoolVar(&compLZO, "comp-lzo", false, "Enable LZO compression")
		fs.BoolVar(&noCompLZO, "no-comp-lzo", false, "Disable comp-lzo (default)")
		fs.Var(&dnsServers, "dns-server", "DNS server to use")
		fs.BoolVar(&noDNSServers, "no-dns-servers", false, "Clear dns-server")
		fs.BoolVar(&duplicateCN, "duplicate-cn", false, "Allow multiple clients with same CN")
		fs.BoolVar(&noDuplicateCN, "no-duplicate-cn", false, "Disable duplicate-cn (default)")
		fs.BoolVar(&blockOutsideDNS, "block-outside-dns", false, "Block DNS outside of tunnel")
		fs.BoolVar(&noBlockOutsideDNS, "no-block-outside-dns", false, "Disable block-outside-dns")
		fs.BoolVar(&clientToClient, "client-to-client", false, "Enable client-to-client communication")
		fs.BoolVar(&noClientToClient, "no-client-to-client", false, "Disable client-to-client (default)")
		fs.BoolVar(&defaultRoute, "default-route", false, "Push default IPv4 route to clients")
		fs.BoolVar(&noDefaultRoute, "no-default-route", false, "Disable default-route")
		fs.BoolVar(&defaultRoute6, "default-route6", false, "Push default IPv6 route to clients")
		fs.BoolVar(&noDefaultRoute6, "no-default-route6", false, "Disable default-route6")
		fs.Var(&routes, "route", "Additional IPv4 route to push to clients")
		fs.BoolVar(&noRoutes, "no-routes", false, "Clear route")
		fs.Var(&route6s, "route6", "Additional IPv6 route to push to clients")
		fs.BoolVar(&noRoute6s, "no-route6s", false, "Clear route6")
		fs.Var(&extraServerConfigs, "extra-server-config", "Extra server configuration")
		fs.BoolVar(&noExtraServerConfigs, "no-extra-server-configs", false, "Clear extra-server-config")
		fs.Var(&extraClientConfigs, "extra-client-config", "Extra client configuration")
		fs.BoolVar(&noExtraClientConfigs, "no-extra-client-configs", false, "Clear extra-client-config")

		if err := fs.Parse(args[1:]); err != nil {
			os.Exit(1)
		}

		// Apply flags to config
		if server != "" {
			config.Server = &server
		}
		config.Protocol = protocol
		config.Port = port
		config.RestartInterval = restartInterval
		if ipv6 {
			config.IPv6 = true
		}
		if noIPv6 {
			config.IPv6 = false
		}
		config.Network = network
		if network6 != "" {
			config.Network6 = &network6
		}
		config.Device = device
		config.Interface = iface
		if nat {
			config.NAT = true
		}
		if noNAT {
			config.NAT = false
		}
		if nat6 {
			b := true
			config.NAT6 = &b
		}
		if noNAT6 {
			b := false
			config.NAT6 = &b
		}
		if compLZO {
			config.CompLZO = true
		}
		if noCompLZO {
			config.CompLZO = false
		}
		if len(dnsServers) > 0 {
			config.DNSServers = dnsServers
		}
		if noDNSServers {
			config.DNSServers = []string{}
		}
		if duplicateCN {
			config.DuplicateCN = true
		}
		if noDuplicateCN {
			config.DuplicateCN = false
		}
		if blockOutsideDNS {
			config.BlockOutsideDNS = true
		}
		if noBlockOutsideDNS {
			config.BlockOutsideDNS = false
		}
		if clientToClient {
			config.ClientToClient = true
		}
		if noClientToClient {
			config.ClientToClient = false
		}
		if defaultRoute {
			config.DefaultRoute = true
		}
		if noDefaultRoute {
			config.DefaultRoute = false
		}
		if defaultRoute6 {
			b := true
			config.DefaultRoute6 = &b
		}
		if noDefaultRoute6 {
			b := false
			config.DefaultRoute6 = &b
		}
		if len(routes) > 0 {
			config.Routes = routes
		}
		if noRoutes {
			config.Routes = []string{}
		}
		if len(route6s) > 0 {
			config.Route6s = route6s
		}
		if noRoute6s {
			config.Route6s = []string{}
		}
		if len(extraServerConfigs) > 0 {
			config.ExtraServerConfigs = extraServerConfigs
		}
		if noExtraServerConfigs {
			config.ExtraServerConfigs = []string{}
		}
		if len(extraClientConfigs) > 0 {
			config.ExtraClientConfigs = extraClientConfigs
		}
		if noExtraClientConfigs {
			config.ExtraClientConfigs = []string{}
		}

		if err := config.FinalizeConfig(); err != nil {
			logError("Failed to finalize config: %v", err)
			os.Exit(1)
		}

		if err := config.Validate(); err != nil {
			logError("Invalid configuration: %v", err)
			os.Exit(1)
		}

		if err := config.SaveConfig(configFile); err != nil {
			logError("Failed to save config: %v", err)
			os.Exit(1)
		}

		useCaPass := caPass && !noCaPass
		err = cmdInit(config, useCaPass)

	case "start":
		fs := flag.NewFlagSet("start", flag.ExitOnError)
		var readonly bool
		fs.BoolVar(&readonly, "readonly", false, "Use /data in readonly mode")
		if err := fs.Parse(args[1:]); err != nil {
			os.Exit(1)
		}

		if _, statErr := os.Stat(easyRsaPKI); os.IsNotExist(statErr) {
			logError("OpenVPN server was not initialized, run init first.")
			os.Exit(1)
		}
		if _, statErr := os.Stat(openvpnDir); os.IsNotExist(statErr) {
			logError("OpenVPN server was not initialized, run init first.")
			os.Exit(1)
		}

		err = cmdStart(config, readonly)

	case "renew-server":
		fs := flag.NewFlagSet("renew-server", flag.ExitOnError)
		var days int
		fs.IntVar(&days, "days", 365*3, "Certificate validity in days")
		if err := fs.Parse(args[1:]); err != nil {
			os.Exit(1)
		}

		if _, statErr := os.Stat(easyRsaPKI); os.IsNotExist(statErr) {
			logError("OpenVPN server was not initialized, run init first.")
			os.Exit(1)
		}

		err = cmdRenewServer(config, days)

	case "new-client":
		fs := flag.NewFlagSet("new-client", flag.ExitOnError)
		var keyPass, noKeyPass bool
		fs.BoolVar(&keyPass, "key-pass", false, "Require password for private key")
		fs.BoolVar(&noKeyPass, "no-key-pass", false, "Disable key-pass (default)")
		if err := fs.Parse(args[1:]); err != nil {
			os.Exit(1)
		}

		if _, statErr := os.Stat(easyRsaPKI); os.IsNotExist(statErr) {
			logError("OpenVPN server was not initialized, run init first.")
			os.Exit(1)
		}

		clientArgs := fs.Args()
		if len(clientArgs) == 0 {
			logError("Client name is required")
			os.Exit(1)
		}
		clientName := clientArgs[0]
		useKeyPass := keyPass && !noKeyPass
		err = cmdNewClient(config, clientName, useKeyPass)

	case "revoke-client":
		fs := flag.NewFlagSet("revoke-client", flag.ExitOnError)
		if err := fs.Parse(args[1:]); err != nil {
			os.Exit(1)
		}

		if _, statErr := os.Stat(easyRsaPKI); os.IsNotExist(statErr) {
			logError("OpenVPN server was not initialized, run init first.")
			os.Exit(1)
		}

		clientArgs := fs.Args()
		if len(clientArgs) == 0 {
			logError("Client name is required")
			os.Exit(1)
		}
		err = cmdRevokeClient(config, clientArgs[0])

	case "renew-client":
		fs := flag.NewFlagSet("renew-client", flag.ExitOnError)
		if err := fs.Parse(args[1:]); err != nil {
			os.Exit(1)
		}

		if _, statErr := os.Stat(easyRsaPKI); os.IsNotExist(statErr) {
			logError("OpenVPN server was not initialized, run init first.")
			os.Exit(1)
		}

		clientArgs := fs.Args()
		if len(clientArgs) == 0 {
			logError("Client name is required")
			os.Exit(1)
		}
		err = cmdRenewClient(config, clientArgs[0])

	case "list-clients":
		if _, statErr := os.Stat(easyRsaPKI); os.IsNotExist(statErr) {
			logError("OpenVPN server was not initialized, run init first.")
			os.Exit(1)
		}
		err = cmdListClients(config)

	case "show-client":
		fs := flag.NewFlagSet("show-client", flag.ExitOnError)
		if err := fs.Parse(args[1:]); err != nil {
			os.Exit(1)
		}

		if _, statErr := os.Stat(easyRsaPKI); os.IsNotExist(statErr) {
			logError("OpenVPN server was not initialized, run init first.")
			os.Exit(1)
		}

		clientArgs := fs.Args()
		if len(clientArgs) == 0 {
			logError("Client name is required")
			os.Exit(1)
		}
		err = cmdShowClient(config, clientArgs[0])

	case "get-client-config":
		fs := flag.NewFlagSet("get-client-config", flag.ExitOnError)
		if err := fs.Parse(args[1:]); err != nil {
			os.Exit(1)
		}

		if _, statErr := os.Stat(easyRsaPKI); os.IsNotExist(statErr) {
			logError("OpenVPN server was not initialized, run init first.")
			os.Exit(1)
		}

		clientArgs := fs.Args()
		if len(clientArgs) == 0 {
			logError("Client name is required")
			os.Exit(1)
		}
		err = cmdGetClientConfig(config, clientArgs[0])

	default:
		logError("Unknown command: %s", command)
		flag.Usage()
		os.Exit(1)
	}

	if err != nil {
		logError("Command failed: %v", err)
		os.Exit(1)
	}
}

// arrayFlags is a custom flag type for repeated string flags
type arrayFlags []string

func (a *arrayFlags) String() string {
	return strings.Join(*a, ",")
}

func (a *arrayFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}
