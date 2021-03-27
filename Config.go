package sshproxy

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/containerssh/sshserver"
)

// Config is the configuration for the SSH proxy module.
type Config struct {
	// Server is the IP address or hostname of the backing server.
	Server string `json:"server" yaml:"server"`
	// Port is the TCP port to connect to.
	Port uint16 `json:"port" yaml:"port" default:"22"`
	// UsernamePassThrough means that the username should be taken from the connecting client.
	UsernamePassThrough bool `json:"usernamePassThrough" yaml:"usernamePassThrough"`
	// Username is the username to pass to the backing SSH server for authentication.
	Username string `json:"username" yaml:"username"`
	// Password is the password to offer to the backing SSH server for authentication.
	Password string `json:"password" yaml:"password"`
	// PrivateKey is the private key to use for authenticating with the backing server.
	PrivateKey string `json:"privateKey" yaml:"privateKey"`
	// AllowedHostKeyFingerprints lists which fingerprints we accept
	AllowedHostKeyFingerprints AllowedHostKeyFingerprints `json:"allowedHostKeyFingerprints" yaml:"allowedHostKeyFingerprints"`
	// Ciphers are the ciphers supported for the backend connection.
	Ciphers sshserver.CipherList `json:"ciphers" yaml:"ciphers" default:"[\"chacha20-poly1305@openssh.com\",\"aes256-gcm@openssh.com\",\"aes128-gcm@openssh.com\",\"aes256-ctr\",\"aes192-ctr\",\"aes128-ctr\"]" comment:"Cipher suites to use"`
	// KexAlgorithms are the key exchange algorithms for the backend connection.
	KexAlgorithms sshserver.KexList `json:"kex" yaml:"kex" default:"[\"curve25519-sha256@libssh.org\",\"ecdh-sha2-nistp521\",\"ecdh-sha2-nistp384\",\"ecdh-sha2-nistp256\"]" comment:"Key exchange algorithms to use"`
	// MACs are the MAC algorithms for the backend connection.
	MACs sshserver.MACList `json:"macs" yaml:"macs" default:"[\"hmac-sha2-256-etm@openssh.com\",\"hmac-sha2-256\"]" comment:"MAC algorithms to use"`
	// HostKeyAlgorithms is a list of algorithms for host keys. The server can offer multiple host keys and this list
	// are the ones we want to accept. The fingerprints for the accepted algorithms should be added to
	// AllowedHostKeyFingerprints.
	HostKeyAlgorithms sshserver.KeyAlgoList `json:"hostKeyAlgos" yaml:"hostKeyAlgos" default:"[\"ssh-rsa-cert-v01@openssh.com\",\"ssh-dss-cert-v01@openssh.com\",\"ecdsa-sha2-nistp256-cert-v01@openssh.com\",\"ecdsa-sha2-nistp384-cert-v01@openssh.com\",\"ecdsa-sha2-nistp521-cert-v01@openssh.com\",\"ssh-ed25519-cert-v01@openssh.com\",\"ssh-rsa\",\"ssh-dss\",\"ssh-ed25519\"]"`
	// Timeout is the time ContainerSSH is willing to wait for the backing connection to be established.
	Timeout time.Duration `json:"timeout" yaml:"timeout" default:"60s"`
	// ClientVersion is the version sent to the server.
	//               Must be in the format of "SSH-protoversion-softwareversion SPACE comments".
	//               See https://tools.ietf.org/html/rfc4253#page-4 section 4.2. Protocol Version Exchange
	//               The trailing CR and LF characters should NOT be added to this string.
	ClientVersion ClientVersion `json:"clientVersion" yaml:"clientVersion" default:"SSH-2.0-ContainerSSH"`
}

// Validate checks the configuration for the backing SSH server.
func (c Config) Validate() error {
	if c.Server == "" {
		return fmt.Errorf("server cannot be empty")
	}
	if c.Port == 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", c.Port)
	}
	if c.Username == "" && !c.UsernamePassThrough {
		return fmt.Errorf("username cannot be empty when usernamePassThrough is not set")
	}
	if len(c.AllowedHostKeyFingerprints) == 0 {
		return fmt.Errorf("allowedHostKeyFingerprints cannot be empty")
	}
	if err := c.Ciphers.Validate(); err != nil {
		return fmt.Errorf("invalid cipher configuration (%w)", err)
	}
	if err := c.KexAlgorithms.Validate(); err != nil {
		return fmt.Errorf("invalid key exchange configuration (%w)", err)
	}
	if err := c.MACs.Validate(); err != nil {
		return fmt.Errorf("invalid MAC configuration (%w)", err)
	}
	if err := c.HostKeyAlgorithms.Validate(); err != nil {
		return fmt.Errorf("invalid host key algorithms (%w)", err)
	}
	if err := c.ClientVersion.Validate(); err != nil {
		return fmt.Errorf("invalid SSH client version (%w)", err)
	}
	return nil
}

func (c Config) loadPrivateKey() (ssh.Signer, error) {
	if c.PrivateKey == "" {
		return nil, nil
	}
	privateKey := c.PrivateKey
	if strings.TrimSpace(privateKey)[:5] != "-----" {
		//Load file
		fh, err := os.Open(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed load private key %s (%w)", privateKey, err)
		}
		privateKeyData, err := ioutil.ReadAll(fh)
		if err != nil {
			_ = fh.Close()
			return nil, fmt.Errorf("failed to load private key %s (%w)", privateKey, err)
		}
		if err = fh.Close(); err != nil {
			return nil, fmt.Errorf("failed to close host key file %s (%w)", privateKey, err)
		}
		privateKey = string(privateKeyData)
	}
	private, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key (%w)", err)
	}
	keyType := private.PublicKey().Type()

	if err := sshserver.KeyAlgo(keyType).Validate(); err != nil {
		return nil, fmt.Errorf("unsupported host key algorithm %s", keyType)
	}
	return private, nil
}
