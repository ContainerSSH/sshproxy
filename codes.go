package sshproxy

// The connection to the designated target server failed. If this message is logged on the debug level the connection will
// be retried. If this message is logged on the error level no more attempts will be made.
const EBackendConnectionFailed = "SSHPROXY_BACKEND_FAILED"

// The operation couldn't complete because the user already disconnected
const EDisconnected = "SSHPROXY_DISCONNECTED"

// The connection could not be established because the backend refused our authentication attempt. This is usually due
// to misconfigured credentials to the backend.
const EBackendHandshakeFailed = "SSHPROXY_BACKEND_HANDSHAKE_FAILED"

// ContainerSSH encountered an unexpected host key fingerprint on the backend while trying to proxy the connection.
// This is either due to a misconfiguration (not all host keys are listed), or a MITM attack between ContainerSSH and
// the target server.
const EInvalidFingerprint = "SSHPROXY_INVALID_FINGERPRINT"

// The client tried to perform an operation after the program has already been started which can only be performed
// before the program is started.
const EProgramAlreadyStarted = "SSHPROXY_PROGRAM_ALREADY_STARTED"

// The client tried to request an action that can only be performed once the program has started before the program
// started.
const EProgramNotStarted = "SSHPROXY_PROGRAM_NOT_STARTED"

// ContainerSSH failed to copy the stdin to the backing connection. This is usually due to an underlying network problem.
const EStdinError = "SSHPROXY_STDIN_ERROR"

// ContainerSSH failed to copy the stdout from the backing connection. This is usually due to an underlying network problem.
const EStdoutError = "SSHPROXY_STDOUT_ERROR"

// ContainerSSH failed to copy the stderr from the backing connection. This is usually due to an underlying network problem.
const EStderrError = "SSHPROXY_STDERR_ERROR"

// ContainerSSH is connecting the backing server.
const MConnecting = "SSHPROXY_CONNECTING"

// Setting the environment variable failed because the backend rejected it.
const ESetEnvFailed = "SSHPROXY_SETENV_FAILED"

// ContainerSSH failed to close the channel on the backend channel. This may be because of an underlying network issue
// or a problem with the backend server.
const EBackingChannelCloseFailed = "SSHPROXY_BACKEND_CHANNEL_CLOSE_FAILED"

// ContainerSSH failed to change the window size on the backend channel. This may be because of an underlying network
// issue, a policy-based rejection from the backend server, or a bug in the backend server.
const EWindowChangeFailed = "SSHPROXY_BACKEND_WINDOW_CHANGE_FAILED"

// ContainerSSH is shutting down and is sending TERM and KILL signals on the backend connection.
const MShutdown = "SSHPROXY_SHUTDOWN"

// ContainerSSH failed to deliver a signal on the backend channel. This may be because of an underlying network issue,
// a policy-based block on the backend server, or a general issue with the backend.
const ESignalFailed = "SSHPROXY_BACKEND_SIGNAL_FAILED"

// The ContainerSSH SSH proxy module failed to close the client connection.
const EChannelCloseFailed = "SSHPROXY_CHANNEL_CLOSE_FAILED"

//
const EBackendSessionFailed = "SSHPROXY_BACKEND_SESSION_FAILED"
