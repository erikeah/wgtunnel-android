package com.zaneschepke.tunnel.backend.dns

import com.zaneschepke.tunnel.DnsConfigManager
import com.zaneschepke.tunnel.model.DnsBootstrapResult
import com.zaneschepke.tunnel.state.RuntimeDnsConfig

class CustomDnsResolver(private val dnsConfig: RuntimeDnsConfig, private val bypass: Boolean) :
    PeerResolver {

    override suspend fun resolve(host: String): DnsBootstrapResult {
        return DnsConfigManager.resolveHostBootstrap(
            host = host,
            protocol = dnsConfig.protocol,
            upstream = dnsConfig.upstream,
            bypass = bypass,
        )
    }
}
