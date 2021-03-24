package sshproxy

import (
	"fmt"
	"regexp"
)

var fingerprintValidator = regexp.MustCompile("^SSH256:[a-zA-Z0-9/+]+$")

// AllowedHostKeyFingerprints is a list of fingerprints that ContainerSSH is allowed to connect to.
type AllowedHostKeyFingerprints []string

// Validate validates the correct format of the host key fingerprints.
func (a AllowedHostKeyFingerprints) Validate() error {
	if len(a) == 0 {
		return fmt.Errorf("no host keys provided")
	}
	for _, fp := range a {
		if !fingerprintValidator.Match([]byte(fp)) {
			return fmt.Errorf("invalid fingerprint: %s (must start with SHA256:)", fp)
		}
	}
	return nil
}
