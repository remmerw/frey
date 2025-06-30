package io.github.remmerw.frey

import io.github.remmerw.frey.DnsData.TXT
import java.net.ConnectException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.CopyOnWriteArraySet
import java.util.function.Supplier


class DnsResolver {
    private val dnsClient = DnsClient(Supplier {
        val list = ArrayList<InetAddress?>()
        list.addAll(STATIC_IPV4_DNS_SERVERS)
        list.addAll(STATIC_IPV6_DNS_SERVERS)
        list
    }, DnsCache())

    private fun retrieveTxtRecords(host: String): MutableSet<String> {
        val txtRecords: MutableSet<String> = HashSet<String>()
        try {
            val result = dnsClient.query(host, DnsRecord.TYPE.TXT)
            val response = result.response
            for (dnsRecord in response.answerSection) {
                val payload = dnsRecord.payload
                if (payload is TXT) {
                    txtRecords.add(payload.text)
                } else {
                    println(payload.toString())
                }
            }
        } catch (ignoreConnectException: ConnectException) {
            // nothing to do here
        } catch (throwable: Throwable) {
            throwable.printStackTrace()
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

    fun resolveDnsAddr(host: String): MutableSet<String> {
        return resolveDnsAddrHost(host, mutableSetOf())
    }


    private fun resolveDnsAddrHost(host: String, hosts: MutableSet<String>): MutableSet<String> {
        val multiAddresses: MutableSet<String> = mutableSetOf()
        // recursion protection
        if (hosts.contains(host)) {
            return multiAddresses
        }
        hosts.add(host)

        val txtRecords = retrieveTxtRecords("_dnsaddr.$host")

        for (txtRecord in txtRecords) {
            try {
                if (txtRecord.startsWith(DNS_ADDR)) {
                    val testRecordReduced: String = txtRecord.replaceFirst(DNS_ADDR, "")
                    multiAddresses.add(testRecordReduced)
                    /* TODO
                    Peeraddr multiaddr = Peeraddr.create(testRecordReduced);
                    if (multiaddr.isDnsaddr()) {
                        String childHost = multiaddr.getDnsHost();
                        multiAddresses.addAll(resolveDnsaddrHost(dnsClient,
                                childHost, hosts));
                    } else {
                         multiAddresses.add(multiaddr);

                    }*/
                }
            } catch (throwable: Throwable) {
                // todo (TAG, "Not supported " + txtRecord);
            }
        }
        return multiAddresses
    }


    companion object {
        val STATIC_IPV4_DNS_SERVERS: MutableSet<Inet4Address?> =
            CopyOnWriteArraySet<Inet4Address?>()
        val STATIC_IPV6_DNS_SERVERS: MutableSet<Inet6Address?> =
            CopyOnWriteArraySet<Inet6Address?>()
        private const val DNS_ADDR = "dnsaddr="
        private const val DNS_LINK = "dnslink="

        init {
            try {
                STATIC_IPV4_DNS_SERVERS.add(DnsUtility.Companion.ipv4From("8.8.8.8"))
                // CLOUDFLARE_DNS_SERVER_IP4 = "1.1.1.1";
            } catch (e: IllegalArgumentException) {
                e.printStackTrace()
                // todo LogUtils.error(TAG, "Could not add static IPv4 DNS Server " + e.getMessage());
            }

            try {
                STATIC_IPV6_DNS_SERVERS.add(DnsUtility.Companion.ipv6From("[2001:4860:4860::8888]"))
            } catch (e: IllegalArgumentException) {
                e.printStackTrace()
                // todo LogUtils.error(TAG, "Could not add static IPv6 DNS Server " + e.getMessage());
            }
        }
    }
}

