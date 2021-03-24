package sshproxy

import (
	"net"
	"sync"

	"github.com/containerssh/log"
	"github.com/containerssh/metrics"
	"github.com/containerssh/sshserver"
)

func New(
	client net.TCPAddr,
	connectionID string,
	config Config,
	logger log.Logger,
	backendRequestsMetric metrics.SimpleCounter,
	backendFailuresMetric metrics.SimpleCounter,
) (
	sshserver.NetworkConnectionHandler,
	error,
) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	privateKey, err := config.loadPrivateKey()
	if err != nil {
		return nil, err
	}

	return &networkConnectionHandler{
		lock:                  &sync.Mutex{},
		client:                client,
		connectionID:          connectionID,
		config:                config,
		logger:                logger,
		backendRequestsMetric: backendRequestsMetric,
		backendFailuresMetric: backendFailuresMetric,
		privateKey:            privateKey,
	}, nil
}
