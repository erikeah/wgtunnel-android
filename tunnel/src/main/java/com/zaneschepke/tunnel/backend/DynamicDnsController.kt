package com.zaneschepke.tunnel.backend

class DynamicDnsController(
    private val failureWindowMs: Long,
    private val minCheckIntervalMs: Long,
) {
    private var failureWindowStartMs = -1L
    private var lastCheckMs = 0L

    fun shouldCheck(now: Long, isHandshakeFailure: Boolean): Boolean {
        if (isHandshakeFailure) {
            if (failureWindowStartMs < 0) {
                failureWindowStartMs = now
            }
        } else {
            failureWindowStartMs = -1L
        }

        val failureEnough =
            failureWindowStartMs > 0 && now - failureWindowStartMs >= failureWindowMs

        val rateLimited = lastCheckMs == 0L || now - lastCheckMs >= minCheckIntervalMs

        return failureEnough && rateLimited
    }

    fun markChecked(now: Long) {
        lastCheckMs = now
    }
}
