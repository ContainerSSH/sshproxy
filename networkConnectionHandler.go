package sshproxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/containerssh/log"
	"github.com/containerssh/metrics"
	"golang.org/x/crypto/ssh"

	"github.com/containerssh/sshserver"
)

type networkConnectionHandler struct {
	lock                  *sync.Mutex
	wg                    *sync.WaitGroup
	client                net.TCPAddr
	connectionID          string
	config                Config
	logger                log.Logger
	backendRequestsMetric metrics.SimpleCounter
	backendFailuresMetric metrics.SimpleCounter
	tcpConn               net.Conn
	disconnected          bool
	privateKey            ssh.Signer
	done                  bool
}

func (s *networkConnectionHandler) OnAuthPassword(_ string, _ []byte) (
	_ sshserver.AuthResponse,
	_ error,
) {
	return sshserver.AuthResponseUnavailable, fmt.Errorf(
		"ssh proxy does not support authentication",
	)
}

func (s *networkConnectionHandler) OnAuthPubKey(_ string, _ string) (
	response sshserver.AuthResponse,
	reason error,
) {
	return sshserver.AuthResponseUnavailable, fmt.Errorf(
		"ssh proxy does not support authentication",
	)
}

func (s *networkConnectionHandler) OnAuthKeyboardInteractive(
	_ string,
	_ func(
		_ string,
		_ sshserver.KeyboardInteractiveQuestions,
	) (answers sshserver.KeyboardInteractiveAnswers, err error),
) (response sshserver.AuthResponse, reason error) {
	return sshserver.AuthResponseUnavailable, fmt.Errorf(
		"ssh proxy does not support authentication",
	)
}

func (s *networkConnectionHandler) OnHandshakeFailed(_ error) {}

func (s *networkConnectionHandler) OnHandshakeSuccess(username string) (
	connection sshserver.SSHConnectionHandler,
	failureReason error,
) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.disconnected {
		return nil, log.NewMessage(
			EDisconnected,
			"could not connect to backend because the user already disconnected",
		)
	}
	sshConn, newChannels, requests, cli, err := s.createBackendSSHConnection(username)
	if err != nil {
		return nil, err
	}

	return &sshConnectionHandler{
		networkHandler: s,
		cli:            cli,
		sshConn:        sshConn,
		newChannels:    newChannels,
		requests:       requests,
		logger:         s.logger,
	}, nil
}

func (s *networkConnectionHandler) createBackendSSHConnection(username string) (
	ssh.Conn,
	<-chan ssh.NewChannel,
	<-chan *ssh.Request,
	*ssh.Client,
	error,
) {
	s.backendRequestsMetric.Increment()
	target := fmt.Sprintf("%s:%d", s.config.Server, s.config.Port)
	tcpConn, err := s.createBackendTCPConnection(username, target)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	s.tcpConn = tcpConn

	sshClientConfig := s.createClientConfig(username)

	sshConn, newChannels, requests, err := ssh.NewClientConn(s.tcpConn, target, sshClientConfig)
	if err != nil {
		s.backendFailuresMetric.Increment(metrics.Label("failure", "handshake"))
		return nil, nil, nil, nil, log.WrapUser(
			err,
			EBackendHandshakeFailed,
			"SSH service is currently unavailable.",
			"Failed to authenticate with the backend.",
		).Label("backend", target)
	}

	cli := ssh.NewClient(sshConn, newChannels, requests)
	return sshConn, newChannels, requests, cli, nil
}

func (s *networkConnectionHandler) createClientConfig(username string) *ssh.ClientConfig {
	if !s.config.UsernamePassThrough {
		username = s.config.Username
	}

	authMethods := []ssh.AuthMethod{
		ssh.Password(s.config.Password),
	}

	if s.privateKey != nil {
		authMethods = append(
			authMethods, ssh.PublicKeys(
				s.privateKey,
			),
		)
	}
	sshClientConfig := &ssh.ClientConfig{
		Config: ssh.Config{
			KeyExchanges: s.config.KexAlgorithms.StringList(),
			Ciphers:      s.config.Ciphers.StringList(),
			MACs:         s.config.MACs.StringList(),
		},
		User: username,
		Auth: authMethods,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			fingerprint := ssh.FingerprintSHA256(key)
			for _, fp := range s.config.AllowedHostKeyFingerprints {
				if fingerprint == fp {
					return nil
				}
			}
			err := log.UserMessage(
				EInvalidFingerprint,
				"SSH service currently unavailable",
				"invalid host key fingerprint: %s",
				fingerprint,
			).Label("fingerprint", fingerprint)
			s.logger.Error(err)
			return err
		},
		ClientVersion:     s.config.ClientVersion.String(),
		HostKeyAlgorithms: s.config.HostKeyAlgorithms.StringList(),
		Timeout:           s.config.Timeout,
	}
	return sshClientConfig
}

func (s *networkConnectionHandler) createBackendTCPConnection(
	_ string,
	target string,
) (net.Conn, error) {
	s.logger.Debug(log.NewMessage(MConnecting, "Connecting to backend server %s", target))
	ctx, cancelFunc := context.WithTimeout(context.Background(), s.config.Timeout)
	defer cancelFunc()
	var networkConnection net.Conn
	var lastError error
loop:
	for {
		networkConnection, lastError = net.Dial("tcp", target)
		if lastError == nil {
			return networkConnection, nil
		}
		s.backendFailuresMetric.Increment(metrics.Label("failure", "tcp"))
		s.logger.Debug(log.WrapUser(
			lastError,
			EBackendConnectionFailed,
			"service currently unavailable",
			"connection to SSH backend failed, retrying in 10 seconds",
		))
		select {
		case <-ctx.Done():
			break loop
		case <-time.After(10 * time.Second):
		}
	}
	err := log.WrapUser(
		lastError,
		EBackendConnectionFailed,
		"service currently unavailable",
		"connection to SSH backend failed, giving up",
	)
	s.logger.Error(err)
	return nil, err
}

func (s *networkConnectionHandler) OnDisconnect() {
	s.lock.Lock()
	s.wg.Wait()
	s.done = true
	defer s.lock.Unlock()
	s.logger.Debug(log.NewMessage(MDisconnected, "Client disconnected."))
	s.disconnected = true
	if s.tcpConn != nil {
		s.logger.Debug(log.NewMessage(MBackendDisconnecting, "Disconnecting backend connection..."))
		if err := s.tcpConn.Close(); err != nil {
			s.logger.Debug(log.Wrap(err, MBackendDisconnectFailed, "Failed to disconnect backend connection."))
		} else {
			s.logger.Debug(log.NewMessage(MBackendDisconnected, "Backend connection disconnected."))
		}
	} else {
		s.logger.Debug(log.NewMessage(MBackendDisconnected, "Backend connection already disconnected."))
	}
}

func (s *networkConnectionHandler) OnShutdown(_ context.Context) {
}
