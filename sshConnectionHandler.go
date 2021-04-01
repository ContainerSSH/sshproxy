package sshproxy

import (
	"context"
	"errors"
	"sync"

	"github.com/containerssh/log"
	"golang.org/x/crypto/ssh"

	"github.com/containerssh/sshserver"
)

type sshConnectionHandler struct {
	networkHandler *networkConnectionHandler
	sshConn        ssh.Conn
	newChannels    <-chan ssh.NewChannel
	requests       <-chan *ssh.Request
	cli            *ssh.Client
	logger         log.Logger
}

func (s *sshConnectionHandler) OnUnsupportedGlobalRequest(_ uint64, _ string, _ []byte) {
}

func (s *sshConnectionHandler) OnUnsupportedChannel(_ uint64, _ string, _ []byte) {
}

func (s *sshConnectionHandler) OnSessionChannel(
	_ uint64,
	extraData []byte,
	session sshserver.SessionChannel,
) (channel sshserver.SessionChannelHandler, failureReason sshserver.ChannelRejection) {
	s.networkHandler.lock.Lock()
	if s.networkHandler.done {
		failureReason = sshserver.NewChannelRejection(
			ssh.ConnectionFailed,
			EShuttingDown,
			"Cannot open session.",
			"Rejected new session because connection is closing.",
		)
		s.networkHandler.lock.Unlock()
		return
	}
	s.networkHandler.wg.Add(1)
	s.networkHandler.lock.Unlock()
	s.logger.Debug(log.NewMessage(MSession, "Opening new session on SSH backend..."))
	backingChannel, requests, err := s.cli.OpenChannel("session", extraData)
	if err != nil {
		realErr := &ssh.OpenChannelError{}
		if errors.As(err, &realErr) {
			failureReason = sshserver.NewChannelRejection(
				realErr.Reason,
				EBackendSessionFailed,
				realErr.Message,
				"Backend rejected channel with message: %s",
				realErr.Message,
			)
		} else {
			failureReason = sshserver.NewChannelRejection(
				ssh.ConnectionFailed,
				EBackendSessionFailed,
				"Cannot open session.",
				"Backend rejected channel with message: %s",
				err.Error(),
			)
		}
		s.logger.Debug(failureReason)
		return nil, failureReason
	}

	sshChannelHandlerInstance := &sshChannelHandler{
		ssh:            s,
		lock:           &sync.Mutex{},
		backingChannel: backingChannel,
		requests:       requests,
		session:        session,
		logger:         s.logger,
		done:           make(chan struct{}),
	}
	go sshChannelHandlerInstance.handleBackendClientRequests(requests, session)

	s.logger.Debug(log.NewMessage(MSessionOpen, "Session open on SSH backend..."))

	return sshChannelHandlerInstance, nil
}

func (s *sshConnectionHandler) OnShutdown(_ context.Context) {
}
