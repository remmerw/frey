package io.github.remmerw.frey

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull


class ResolverTest {
    
    @Test
    fun test() {
        val dnsResolver = DnsResolver()
        val result = dnsResolver.resolveDnsAddr("bootstrap.libp2p.io")
        assertNotNull(result)
        assertFalse(result.isEmpty())
        result.forEach { text -> println(text) }
    }
}
