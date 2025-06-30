package io.github.remmerw.frey

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull


class DnsResolverTest {

    @Test
    fun testDnsAddr() : Unit = runBlocking(Dispatchers.IO) {
        val resolver = DnsResolver()
        val result = resolver.resolveDnsAddr("bootstrap.libp2p.io")
        assertNotNull(result)
        assertFalse(result.isEmpty())
        result.forEach { text -> println(text) }
    }

    @Test
    fun testAAAARecord() : Unit = runBlocking(Dispatchers.IO) {
        val resolver = DnsResolver()
        val result = resolver.retrieveAAAARecord("www.welt.de")
        assertNotNull(result)
        assertFalse(result.isEmpty())
        result.forEach { text -> println(text) }
    }

    @Test
    fun testARecord() : Unit = runBlocking(Dispatchers.IO) {
        val resolver = DnsResolver()
        val result = resolver.retrieveARecord("www.welt.de")
        assertNotNull(result)
        assertFalse(result.isEmpty())
        result.forEach { text -> println(text) }
    }
}
