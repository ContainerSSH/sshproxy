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

const EBackendRequestFailed = "SSHPROXY_BACKEND_REQUEST_FAILED"

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

// ContainerSSH failed to open a session on the backend server with the SSH Proxy backend.
const EBackendSessionFailed = "SSHPROXY_BACKEND_SESSION_FAILED"

// The ContainerSSH SSH proxy backend is opening a new session.
const MSession = "SSHPROXY_SESSION"

// The ContainerSSH SSH proxy backend has opened a new session.
const MSessionOpen = "SSHPROXY_SESSION_OPEN"

// The ContainerSSH SSH proxy backend is closing a session.
const MSessionClose = "SSHPROXY_SESSION_CLOSE"

// The ContainerSSH SSH proxy backend has closed a session.
const MSessionClosed = "SSHPROXY_SESSION_CLOSED"

// ContainerSSH failed to close the session channel on the backend. This may be because of an underlying network issue
// or a problem with the backend server.
const ESessionCloseFailed = "SSHPROXY_SESSION_CLOSE_FAILED"

// The ContainerSSH SSH proxy backend has received an exit-signal message.
const MExitSignal = "SSHPROXY_EXIT_SIGNAL"

// The ContainerSSH SSH proxy backend has received an exit-signal message, but failed to decode the message. This is
// most likely due to a bug in the backend SSH server.
const MExitSignalDecodeFailed = "SSHPROXY_EXIT_SIGNAL_DECODE_FAILED"

// The ContainerSSH SSH proxy backend has received an exit-status message.
const MExitStatus = "SSHPROXY_EXIT_STATUS"

// The ContainerSSH SSH proxy backend has received an exit-status message, but failed to decode the message. This is
// most likely due to a bug in the backend SSH server.
const MExitStatusDecodeFailed = "SSHPROXY_EXIT_STATUS_DECODE_FAILED"

// The ContainerSSH SSH proxy received a disconnect from the client.
const MDisconnected = "SSHPROXY_DISCONNECTED"

// The action cannot be performed because the connection is shutting down.
const EShuttingDown = "SSHPROXY_SHUTTING_DOWN"

// The backend closed the SSH session towards ContainerSSH.
const MBackendSessionClosed = "SSHPROXY_BACKEND_SESSION_CLOSED"

// ContainerSSH is closing the session towards the backend service.
const MBackendSessionClosing = "SSHPROXY_BACKEND_SESSION_CLOSING"

// ContainerSSH could not close the session towards the backend service.
const EBackendCloseFailed = "SSHPROXY_BACKEND_SESSION_CLOSE_FAILED"

const MBackendDisconnecting = "SSHPROXY_BACKEND_DISCONNECTING"

const MBackendDisconnectFailed = "SSHPROXY_BACKEND_DISCONNECT_FAILED"

const MBackendDisconnected = "SSHPROXY_BACKEND_DISCONNECTED"

const MStderrComplete = "SSHPROXY_STDERR_COMPLETE"

const MStdoutComplete = "SSHPROXY_STDOUT_COMPLETE"
