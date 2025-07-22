package io.github.remmerw.frey

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue


class DnsResolverTest {

    @Test
    fun testDnsAddr() {
        val resolver = DnsResolver()
        val result = resolver.resolveDnsAddr("bootstrap.libp2p.io")
        assertNotNull(result)
        assertFalse(result.isEmpty())
        result.forEach { text -> println(text) }
    }

    @Test
    fun testDnsLinkFailure() {
        val resolver = DnsResolver()
        val result = resolver.resolveDnsLink("bootstrap.libp2p.io") // this fails, not valid
        assertNotNull(result)
        assertTrue(result.isEmpty())
    }


    @Test
    fun testTXTRecord() {
        val resolver = DnsResolver()
        val result = resolver.retrieveTxtRecords("_dnsaddr.bootstrap.libp2p.io")
        assertNotNull(result)
        assertFalse(result.isEmpty())
        result.forEach { text -> println(text) }
    }

    @Test
    fun testAAAARecord() {
        val resolver = DnsResolver(defaultDnsServerIpv6())
        val addresses = resolver.retrieveAAAARecord("www.welt.de")
        assertNotNull(addresses)
        assertFalse(addresses.isEmpty())
    }

    @Test
    fun testARecord() {
        val resolver = DnsResolver(defaultDnsServerIpv4())
        val addresses = resolver.retrieveARecord("www.welt.de")
        assertNotNull(addresses)
        assertFalse(addresses.isEmpty())
    }
}
