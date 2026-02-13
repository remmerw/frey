@file:Suppress("unused")

package io.github.remmerw.frey

import io.github.remmerw.frey.DnsData.TXT
import io.github.remmerw.frey.DnsResolver.Companion.IPV4_DNS_SERVERS
import io.github.remmerw.frey.DnsResolver.Companion.IPV6_DNS_SERVERS
import java.net.InetSocketAddress

fun defaultDnsServer(): List<InetSocketAddress> {
    val list = ArrayList<InetSocketAddress>()
    list.addAll(IPV4_DNS_SERVERS)
    list.addAll(IPV6_DNS_SERVERS)
    return list
}

fun defaultDnsServerIpv6(): List<InetSocketAddress> {
    val list = ArrayList<InetSocketAddress>()
    list.addAll(IPV6_DNS_SERVERS)
    return list
}

fun defaultDnsServerIpv4(): List<InetSocketAddress> {
    val list = ArrayList<InetSocketAddress>()
    list.addAll(IPV4_DNS_SERVERS)
    return list
}

class DnsResolver(dnsServer: List<InetSocketAddress> = defaultDnsServer()) {
    private val dnsClient = DnsClient(dnsServer, DnsCache())

    fun retrieveARecord(host: String): List<ByteArray> {
        val response: MutableList<ByteArray> = mutableListOf()
        try {
            val result = dnsClient.query(host, DnsRecord.TYPE.A)
            for (dnsRecord in result.response.answerSection) {
                val payload = dnsRecord.payload
                if (payload is DnsData.A) {
                    response.add(payload.bytes())
                }
            }
        } catch (throwable: Throwable) {
            debug(throwable)
        }
        return response
    }


    fun retrieveAAAARecord(host: String): List<ByteArray> {
        val response: MutableList<ByteArray> = mutableListOf()
        try {
            val result = dnsClient.query(host, DnsRecord.TYPE.AAAA)

            for (dnsRecord in result.response.answerSection) {
                val payload = dnsRecord.payload
                if (payload is DnsData.AAAA) {
                    response.add(payload.bytes())
                }
            }
        } catch (throwable: Throwable) {
            debug(throwable)
        }
        return response
    }

    fun retrieveTxtRecords(host: String): MutableSet<String> {
        val txtRecords: MutableSet<String> = mutableSetOf()
        try {
            val result = dnsClient.query(host, DnsRecord.TYPE.TXT)
            val response = result.response
            for (dnsRecord in response.answerSection) {
                val payload = dnsRecord.payload
                if (payload is TXT) {
                    txtRecords.add(payload.text)
                }
            }
        } catch (throwable: Throwable) {
            debug(throwable)
        }
        return txtRecords
    }

    fun resolveDnsLink(host: String): String {
        val txtRecords = retrieveTxtRecords("_dnslink.$host")
        for (txtRecord in txtRecords) {
            if (txtRecord.startsWith(DNS_LINK)) {
                return txtRecord.replaceFirst(DNS_LINK, "")
            }
        }
        return ""
    }

    fun resolveDnsAddr(host: String): Set<String> {
        val multiAddresses: MutableSet<String> = mutableSetOf()

        val txtRecords = retrieveTxtRecords("_dnsaddr.$host")

        for (txtRecord in txtRecords) {
            if (txtRecord.startsWith(DNS_ADDR)) {
                val testRecordReduced: String = txtRecord.replaceFirst(DNS_ADDR, "")
                multiAddresses.add(testRecordReduced)
            }
        }
        return multiAddresses
    }


    companion object {
        val IPV4_DNS_SERVERS: MutableSet<InetSocketAddress> = mutableSetOf()
        val IPV6_DNS_SERVERS: MutableSet<InetSocketAddress> = mutableSetOf()
        private const val DNS_ADDR = "dnsaddr="
        private const val DNS_LINK = "dnslink="

        init {
            try {
                IPV4_DNS_SERVERS.add(InetSocketAddress("8.8.8.8", 53))
                // CLOUDFLARE_DNS_SERVER_IP4 = "1.1.1.1";
            } catch (e: IllegalArgumentException) {
                debug(e)
            }

            try {
                IPV6_DNS_SERVERS.add(InetSocketAddress("[2001:4860:4860::8888]", 53))
            } catch (e: IllegalArgumentException) {
                debug(e)
            }
        }
    }
}

// "In the absence of these mechanisms, QUIC endpoints SHOULD NOT send IP
//   packets larger than 1280 bytes.  Assuming the minimum IP header size,
//   this results in a QUIC maximum packet size of 1232 bytes for IPv6 and
//   1252 bytes for IPv4."
// As it is not know (yet) whether running over IP4 or IP6, take the smallest of the two:
const val MAX_PACKET_SIZE: Int = 1232
const val SO_TIMEOUT: Int = 3000

internal fun debug(throwable: Throwable) {
    if (ERROR) {
        throwable.printStackTrace()
    }
}

private const val ERROR: Boolean = true
