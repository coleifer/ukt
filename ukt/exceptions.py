# Base exception class.
class KTError(Exception): pass

# Server returned an error response, e.g., there is a problem with the request.
class ProtocolError(KTError): pass

# Lost connection to the server.
class ServerConnectionError(KTError): pass

# Connection may be OK, but we timed-out for some reason. Sockets that time out
# are closed and removed from the pool of healthy connections.
class ServerTimeoutError(ServerConnectionError): pass

# Indicates an error/unexpected response from the server.
class ServerError(KTError): pass

# Indicate time-out waiting for signal.
class SignalTimeout(KTError): pass
