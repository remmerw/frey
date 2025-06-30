package io.github.remmerw.frey

import io.github.remmerw.frey.DnsData.TXT
import io.ktor.network.sockets.InetSocketAddress


class DnsResolver {
    private val dnsClient = DnsClient({
        val list = ArrayList<InetSocketAddress>()
        list.addAll(STATIC_IPV4_DNS_SERVERS)
        list.addAll(STATIC_IPV6_DNS_SERVERS)
        list
    }, DnsCache())


    // TODO not yet working
    suspend fun retrieveARecord(host: String): List<String> {
        val response: MutableList<String> = mutableListOf()
        val result = dnsClient.query(host, DnsRecord.TYPE.A)
        for (dnsRecord in result.response.answerSection) {
            val payload = dnsRecord.payload
            if (payload is DnsData.UNKNOWN) {
                response.add(payload.bytes().decodeToString())
            } else {
                println(payload.toString()) // todo
            }
        }
        return response
    }


    // TODO not yet working
    suspend fun retrieveAAAARecord(host: String): List<String> {
        val response: MutableList<String> = mutableListOf()
        val result = dnsClient.query(host, DnsRecord.TYPE.AAAA)

        for (dnsRecord in result.response.answerSection) {
            val payload = dnsRecord.payload
            if (payload is DnsData.UNKNOWN) {
                response.add(payload.bytes().decodeToString())
            } else {
                println(payload.toString()) // todo
            }
        }
        return response
    }

    suspend fun retrieveTxtRecords(host: String): MutableSet<String> {
        val txtRecords: MutableSet<String> = mutableSetOf()
        try {
            val result = dnsClient.query(host, DnsRecord.TYPE.TXT)
            val response = result.response
            for (dnsRecord in response.answerSection) {
                val payload = dnsRecord.payload
                if (payload is TXT) {
                    txtRecords.add(payload.text)
                } else {
                    println(payload.toString()) // todo
                }
            }
        } catch (_: Exception) {
            // nothing to do here
        } catch (throwable: Throwable) {
            throwable.printStackTrace()
        }
        return txtRecords
    }

    suspend fun resolveDnsLink(host: String): String {
        val txtRecords = retrieveTxtRecords("_dnslink.$host")
        for (txtRecord in txtRecords) {
            if (txtRecord.startsWith(DNS_LINK)) {
                return txtRecord.replaceFirst(DNS_LINK, "")
            }
        }
        return ""
    }

    suspend fun resolveDnsAddr(host: String): Set<String> {
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
        val STATIC_IPV4_DNS_SERVERS: MutableSet<InetSocketAddress> = mutableSetOf()
        val STATIC_IPV6_DNS_SERVERS: MutableSet<InetSocketAddress> = mutableSetOf()
        private const val DNS_ADDR = "dnsaddr="
        private const val DNS_LINK = "dnslink="

        init {
            try {
                STATIC_IPV4_DNS_SERVERS.add(InetSocketAddress("8.8.8.8", 53))
                // CLOUDFLARE_DNS_SERVER_IP4 = "1.1.1.1";
            } catch (e: IllegalArgumentException) {
                e.printStackTrace()
                // todo LogUtils.error(TAG, "Could not add static IPv4 DNS Server " + e.getMessage());
            }

            try {
                STATIC_IPV6_DNS_SERVERS.add(InetSocketAddress("[2001:4860:4860::8888]", 53))
            } catch (e: IllegalArgumentException) {
                e.printStackTrace()
                // todo LogUtils.error(TAG, "Could not add static IPv6 DNS Server " + e.getMessage());
            }
        }
    }
}

