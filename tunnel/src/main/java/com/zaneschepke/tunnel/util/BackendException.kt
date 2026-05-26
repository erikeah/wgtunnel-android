package com.zaneschepke.tunnel.util

sealed class BackendException : Exception() {
    class StateConflict(override val message: String) : BackendException()

    class InternalError(override val message: String) : BackendException()

    class Unauthorized(override val message: String) : BackendException()

    class Socks5PortUnavailable(override val message: String, val port: Int) : BackendException()

    class HttpPortUnavailable(override val message: String, val port: Int) : BackendException()
}
