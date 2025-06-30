package io.github.remmerw.frey

import io.github.remmerw.frey.DnsMessage.ResponseCode
import io.github.remmerw.frey.DnsName.Companion.from
import io.ktor.util.collections.ConcurrentSet
import java.net.InetAddress
import kotlin.random.Random

/**
 * A minimal DNS client for TXT lookups, with IDN support.
 * This circumvents the missing javax.naming package on android.
 */
class DnsClient internal constructor(
    private val addresses: () -> (List<InetAddress>),
    val dnsCache: DnsCache
) {
    /**
     * The internal random class for sequence generation.
     */
    private val random: Random = Random

    private val nonRaServers: MutableSet<InetAddress> = ConcurrentSet()

    fun onResponse(requestMessage: DnsMessage, responseMessage: DnsQueryResult) {
        val q = requestMessage.question
        if (isResponseCacheable(q, responseMessage)) {
            dnsCache.put(requestMessage.asNormalizedVersion(), responseMessage)
        }
    }

    /**
     * Query the system nameservers for a single entry of the class IN
     * (which is used for MX, SRV, A, AAAA and most other RRs).
     *
     * @param name The DNS name to request.
     * @param type The DNS type to request (SRV, A, AAAA, ...).
     * @return The response (or null on timeout/error).
     */

    fun query(name: CharSequence, type: DnsRecord.TYPE): DnsQueryResult {
        val q: DnsQuestion = DnsQuestion.Companion.create(from(name), type)
        return query(q)
    }


    private fun query(q: DnsQuestion): DnsQueryResult {
        val query = buildMessage(q)
        return query(query)
    }

    /**
     * Builds a [DnsMessage] object carrying the given Question.
     *
     * @param question [DnsQuestion] to be put in the DNS request.
     * @return A [DnsMessage] requesting the answer for the given Question.
     */
    private fun buildMessage(question: DnsQuestion): DnsMessage.Builder {
        val message: DnsMessage.Builder = DnsMessage.Companion.builder()
        message.setQuestion(question)
        message.setId(random.nextInt())
        newQuestion(message)
        return message
    }


    private fun query(query: DnsMessage, address: InetAddress): DnsQueryResult {
        val responseMessage: DnsQueryResult = DnsUtility.Companion.query(query, address)
        onResponse(query, responseMessage)
        return responseMessage
    }

    private val serverAddresses: List<InetAddress>
        get() = addresses.invoke()


    private fun query(queryBuilder: DnsMessage.Builder): DnsQueryResult {
        val q: DnsMessage = newQuestion(queryBuilder).build()
        // While this query method does in fact re-use query(Question, String)
        // we still do a cache lookup here in order to avoid unnecessary
        // findDNS()calls, which are expensive on Android. Note that we do not
        // put the results back into the Cache, as this is already done by
        // query(Question, String).
        var dnsQueryResult = dnsCache.get(q)
        if (dnsQueryResult != null) {
            return dnsQueryResult
        }


        var ioException: Exception? = null
        for (dns in serverAddresses) {
            if (nonRaServers.contains(dns)) {
                println("Skipping $dns because it was marked as \"recursion not available\"")  // todo
                continue
            }

            try {
                dnsQueryResult = query(q, dns)
            } catch (exception: Exception) {
                ioException = exception
                continue
            }

            val responseMessage = dnsQueryResult.response
            if (!responseMessage.recursionAvailable) {
                val newRaServer = nonRaServers.add(dns)
                if (newRaServer) {
                    println(
                        "The DNS server " + dns
                                + " returned a response without the \"recursion available\" (RA) flag " +
                                "set. This likely indicates a misconfiguration because the " +
                                "server is not suitable for DNS resolution"
                    )
                }
                continue
            }

            when (responseMessage.responseCode) {
                ResponseCode.NO_ERROR, ResponseCode.NX_DOMAIN -> {}
                else -> {
                    println(
                        "Response from " + dns + " asked for " + q.question +
                                " with error code: " + responseMessage.responseCode + '.'
                    )
                    // todo
                }
            }

            return dnsQueryResult
        }

        if (ioException != null) {
            throw ioException
        }

        throw IllegalArgumentException("No DNS server could be queried")
    }

    companion object {
        /**
         * Whether a response from the DNS system should be cached or not.
         *
         * @param q      The question the response message should answer.
         * @param result The DNS query result.
         * @return True, if the response should be cached, false otherwise.
         */
        private fun isResponseCacheable(q: DnsQuestion, result: DnsQueryResult): Boolean {
            val dnsMessage = result.response
            for (dnsRecord in dnsMessage.answerSection) {
                if (dnsRecord.isAnswer(q)) {
                    return true
                }
            }
            return false
        }

        private fun newQuestion(message: DnsMessage.Builder): DnsMessage.Builder {
            message.setRecursionDesired()
            val askForDnssec = false
            message.ednsBuilder.setUdpPayloadSize(DnsUtility.Companion.UDP_PAYLOAD_SIZE)
                .setDnssecOk(askForDnssec)
            return message
        }
    }
}
