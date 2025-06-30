package io.github.remmerw.frey

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue


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
    fun testDnsLinkFailure() : Unit = runBlocking(Dispatchers.IO) {
        val resolver = DnsResolver()
        val result = resolver.resolveDnsLink("bootstrap.libp2p.io") // this fails, not valid
        assertNotNull(result)
        assertTrue(result.isEmpty())
    }


    @Test
    fun testTXTRecord() : Unit = runBlocking(Dispatchers.IO) {
        val resolver = DnsResolver()
        val result = resolver.retrieveTxtRecords("_dnsaddr.bootstrap.libp2p.io")
        assertNotNull(result)
        assertFalse(result.isEmpty())
        result.forEach { text -> println(text) }
    }

    @Test
    fun testAAAARecord() : Unit = runBlocking(Dispatchers.IO) {
        val resolver = DnsResolver()
        val addresses = resolver.retrieveAAAARecord("www.welt.de")
        assertNotNull(addresses)
        assertFalse(addresses.isEmpty())
    }

    @Test
    fun testARecord() : Unit = runBlocking(Dispatchers.IO) {
        val resolver = DnsResolver()
        val addresses = resolver.retrieveARecord("www.welt.de")
        assertNotNull(addresses)
        assertFalse(addresses.isEmpty())
    }
}
