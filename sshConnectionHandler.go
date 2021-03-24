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
	backingChannel, requests, err := s.cli.OpenChannel("session", extraData)
	if err != nil {
		realErr := &ssh.OpenChannelError{}
		if errors.As(err, &realErr) {
			return nil, sshserver.NewChannelRejection(
				realErr.Reason,
				EBackendSessionFailed,
				realErr.Message,
				"Backend rejected channel with message: %s",
				realErr.Message,
			)
		}
		return nil, sshserver.NewChannelRejection(
			ssh.ConnectionFailed,
			EBackendSessionFailed,
			"Cannot open session.",
			"Backend rejected channel with message: %s",
			err.Error(),
		)
	}

	go s.handleBackendClientRequests(requests, session)

	return &sshChannelHandler{
		lock:           &sync.Mutex{},
		backingChannel: backingChannel,
		requests:       requests,
		session:        session,
		logger:         s.logger,
		done:           make(chan struct{}),
	}, nil
}

func (s *sshConnectionHandler) handleBackendClientRequests(
	requests <-chan *ssh.Request,
	session sshserver.SessionChannel,
) {
	func() {
		for {
			request, ok := <-requests
			if !ok {
				return
			}
			switch request.Type {
			case "exit-status":
				s.handleExitStatusFromBackend(request, session)
			case "exit-signal":
				s.handleExitSignalFromBackend(request, session)
			default:
				if request.WantReply {
					_ = request.Reply(false, []byte{})
				}
			}
		}
	}()
}

func (s *sshConnectionHandler) handleExitStatusFromBackend(request *ssh.Request, session sshserver.SessionChannel) {
	exitStatus := &exitStatusPayload{}
	if err := ssh.Unmarshal(request.Payload, exitStatus); err != nil {
		if request.WantReply {
			_ = request.Reply(false, []byte{})
		}
	} else {
		session.ExitStatus(
			exitStatus.ExitStatus,
		)
		if request.WantReply {
			_ = request.Reply(true, []byte{})
		}
	}
}

func (s *sshConnectionHandler) handleExitSignalFromBackend(request *ssh.Request, session sshserver.SessionChannel) {
	exitSignal := &exitSignalPayload{}
	if err := ssh.Unmarshal(request.Payload, exitSignal); err != nil {
		if request.WantReply {
			_ = request.Reply(false, []byte{})
		}
	} else {
		session.ExitSignal(
			exitSignal.Signal,
			exitSignal.CoreDumped,
			exitSignal.ErrorMessage,
			exitSignal.LanguageTag,
		)
		if request.WantReply {
			_ = request.Reply(true, []byte{})
		}
	}
}

func (s *sshConnectionHandler) OnShutdown(_ context.Context) {}
