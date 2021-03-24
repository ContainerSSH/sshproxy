package sshproxy

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/containerssh/log"
	"golang.org/x/crypto/ssh"

	"github.com/containerssh/sshserver"
)

type sshChannelHandler struct {
	lock           *sync.Mutex
	backingChannel ssh.Channel
	requests       <-chan *ssh.Request
	session        sshserver.SessionChannel
	started        bool
	logger         log.Logger
	done           chan struct{}
	exited         bool
}

func (s *sshChannelHandler) streamStdio() error {
	if s.started {
		err := log.UserMessage(EProgramAlreadyStarted, "Cannot start new program after program has started.", "Client tried to start a program after the program was already started.")
		s.logger.Debug(err)
		return err
	}
	s.started = true
	go func() {
		if _, err := io.Copy(s.backingChannel, s.session.Stdin()); err != nil {
			if !errors.Is(err, io.EOF) {
				s.logger.Debug(log.Wrap(err, EStdinError, "Error copying stdin"))
			}
		}
		if err := s.backingChannel.CloseWrite(); err != nil && !errors.Is(err, io.EOF) {
			s.logger.Debug(log.NewMessage(
				EBackingChannelCloseFailed,
				"Failed to close the backend SSH channel for writing.",
			))
		}
		if err := s.backingChannel.Close(); err != nil && !errors.Is(err, io.EOF) {
			s.logger.Debug(log.NewMessage(
				EBackingChannelCloseFailed,
				"Failed to close the backend SSH channel.",
			))
		}
	}()
	outWg := &sync.WaitGroup{}
	outWg.Add(2)
	go func() {
		if _, err := io.Copy(s.session.Stdout(), s.backingChannel); err != nil {
			if !errors.Is(err, io.EOF) {
				s.logger.Debug(log.Wrap(err, EStdoutError, "Error copying stdout"))
			}
		}
		outWg.Done()
	}()
	go func() {
		if _, err := io.Copy(s.session.Stderr(), s.backingChannel.Stderr()); err != nil {
			if !errors.Is(err, io.EOF) {
				s.logger.Debug(log.Wrap(err, EStderrError, "Error copying stdout"))
			}
		}
		outWg.Done()
	}()
	go func() {
		outWg.Wait()
		if err := s.session.CloseWrite(); err != nil && !errors.Is(err, io.EOF) {
			s.logger.Debug(log.NewMessage(
				EChannelCloseFailed,
				"Failed to close the SSH channel for writing.",
			))
		}
		if err := s.session.Close(); err != nil && !errors.Is(err, io.EOF) {
			s.logger.Debug(log.NewMessage(
				EChannelCloseFailed,
				"Failed to close the SSH channel.",
			))
		}
	}()
	return nil
}

func (s *sshChannelHandler) OnUnsupportedChannelRequest(_ uint64, _ string, _ []byte) {}

func (s *sshChannelHandler) OnFailedDecodeChannelRequest(
	_ uint64,
	_ string,
	_ []byte,
	_ error,
) {
}

func (s *sshChannelHandler) sendRequest(name string, payload interface{}) error {
	var marshalledPayload []byte
	if payload != nil {
		marshalledPayload = ssh.Marshal(payload)
	}
	success, err := s.backingChannel.SendRequest(name, true, marshalledPayload)
	if err != nil {
		err := log.WrapUser(err, ESetEnvFailed, "Cannot set environment variable.", "Setting environment variable on backing channel failed.")
		s.logger.Debug(err)
		return err
	}
	if !success {
		err := log.UserMessage(ESetEnvFailed, "Cannot set environment variable.", "Setting environment variable on backing channel failed.")
		s.logger.Debug(err)
		return err
	}
	return nil
}

func (s *sshChannelHandler) OnEnvRequest(_ uint64, name string, value string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.started {
		err := log.UserMessage(EProgramAlreadyStarted, "Cannot set environment variable after program has started.", "Client tried to set environment variables after the program was already started.")
		s.logger.Debug(err)
		return err
	}
	payload := envRequestPayload{
		Name:  name,
		Value: value,
	}
	return s.sendRequest("env", payload)
}

func (s *sshChannelHandler) OnPtyRequest(
	_ uint64,
	term string,
	columns uint32,
	rows uint32,
	width uint32,
	height uint32,
	modeList []byte,
) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.started {
		err := log.UserMessage(EProgramAlreadyStarted, "Cannot request PTY after program has started.", "Client tried request PTY after the program was already started.")
		s.logger.Debug(err)
		return err
	}
	payload := ptyRequestPayload{
		Term:     term,
		Columns:  columns,
		Rows:     rows,
		Width:    width,
		Height:   height,
		ModeList: modeList,
	}
	return s.sendRequest("pty-req", payload)
}

func (s *sshChannelHandler) OnExecRequest(_ uint64, program string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.started {
		err := log.UserMessage(EProgramAlreadyStarted, "Cannot start a program after another program has started.", "Client tried start a second program after the program was already started.")
		s.logger.Debug(err)
		return err
	}
	payload := execRequestPayload{
		Exec: program,
	}
	err := s.sendRequest("exec", payload)
	if err != nil {
		return err
	}
	return s.streamStdio()
}

func (s *sshChannelHandler) OnShell(_ uint64) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.started {
		err := log.UserMessage(EProgramAlreadyStarted, "Cannot start a program after another program has started.", "Client tried start a second program after the program was already started.")
		s.logger.Debug(err)
		return err
	}
	err := s.sendRequest("shell", nil)
	if err != nil {
		return err
	}
	return s.streamStdio()
}

func (s *sshChannelHandler) OnSubsystem(_ uint64, subsystem string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.started {
		err := log.UserMessage(EProgramAlreadyStarted, "Cannot start a program after another program has started.", "Client tried start a second program after the program was already started.")
		s.logger.Debug(err)
		return err
	}
	payload := subsystemRequestPayload{
		Subsystem: subsystem,
	}
	err := s.sendRequest("subsystem", payload)
	if err != nil {
		return err
	}
	return s.streamStdio()
}

func (s *sshChannelHandler) OnSignal(_ uint64, signal string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if !s.started {
		err := log.UserMessage(EProgramNotStarted, "Cannot signal before program has started.", "Client tried send a signal before the program was started.")
		s.logger.Debug(err)
		return err
	}
	payload := signalRequestPayload{
		Signal: signal,
	}
	return s.sendRequest("signal", payload)
}

func (s *sshChannelHandler) OnWindow(_ uint64, columns uint32, rows uint32, width uint32, height uint32) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if !s.started {
		err := log.UserMessage(
			EProgramNotStarted,
			"Cannot resize window before program has started.",
			"Client tried request a window change before the program was started.",
		)
		s.logger.Debug(err)
		return err
	}
	payload := windowRequestPayload{
		Columns: columns,
		Rows:    rows,
		Width:   width,
		Height:  height,
	}
	if err := s.sendRequest("window-change", payload); err != nil {
		err := log.WrapUser(
			err,
			EWindowChangeFailed,
			"Cannot change window size.",
			"ContainerSSH cannot change the window size because of an error on the backend connection.",
		)
		s.logger.Debug(err)
		return err
	}
	return nil
}

func (s *sshChannelHandler) OnClose() {
	s.lock.Lock()
	defer s.lock.Unlock()
	if err := s.backingChannel.Close(); err != nil && !errors.Is(err, io.EOF) {
		s.logger.Debug(log.NewMessage(EBackingChannelCloseFailed, "Failed to close backing channel."))
	}
	close(s.done)
	s.exited = true
}

func (s *sshChannelHandler) OnShutdown(shutdownContext context.Context) {
	s.lock.Lock()
	s.logger.Debug(log.NewMessage(MShutdown, "Sending TERM signal on backing channel."))
	if err := s.sendRequest("signal", signalRequestPayload{
		Signal: "TERM",
	}); err != nil {
		s.logger.Debug(log.Wrap(err, ESignalFailed, "Failed to deliver TERM signal to backend."))
	}
	s.lock.Unlock()

	select {
	case <-shutdownContext.Done():
		s.lock.Lock()
		if !s.exited {
			s.logger.Debug(log.NewMessage(MShutdown, "Sending KILL signal on backing channel."))
			if err := s.sendRequest("signal", signalRequestPayload{
				Signal: "KILL",
			}); err != nil {
				s.logger.Debug(log.Wrap(err, ESignalFailed, "Failed to deliver KILL signal to backend."))
			}
		}
		s.lock.Unlock()
	case <-s.done:
	}
}
