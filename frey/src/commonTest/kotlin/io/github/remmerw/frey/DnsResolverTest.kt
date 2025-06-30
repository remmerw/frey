package io.github.remmerw.frey

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull


class DnsResolverTest {

    @Test
    fun test() {
        val resolver = DnsResolver()
        val result = resolver.resolveDnsAddr("bootstrap.libp2p.io")
        assertNotNull(result)
        assertFalse(result.isEmpty())
        result.forEach { text -> println(text) }
    }
}
