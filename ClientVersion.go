package sshproxy

import (
	"fmt"
	"regexp"
)

var clientVersionRegexp = regexp.MustCompile(`^SSH-2.0-[a-zA-Z0-9]+(| [a-zA-Z0-9- _.]+)$`)

// ClientVersion is a string that is issued to the client when connecting.
type ClientVersion string

// Validate checks if the client version conforms to RFC 4253 section 4.2.
// See https://tools.ietf.org/html/rfc4253#page-4
func (s ClientVersion) Validate() error {
	if !clientVersionRegexp.MatchString(string(s)) {
		return fmt.Errorf("invalid client version string (%s), see https://tools.ietf.org/html/rfc4253#page-4 section 4.2. for details", s)
	}
	return nil
}

// String returns a string from the ClientVersion.
func (s ClientVersion) String() string {
	return string(s)
}
