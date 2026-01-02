package io.github.remmerw.frey

import java.util.concurrent.ConcurrentHashMap
import kotlin.time.DurationUnit
import kotlin.time.TimeSource
import kotlin.time.toDuration

/**
 * Cache for DNS Entries. Implementations must be thread safe.
 */
class DnsCache {
    /**
     * The backend cache.
     */
    private val backend: MutableMap<DnsMessage, DnsQueryResult> = ConcurrentHashMap()

    /**
     * Internal miss count.
     */
    private var missCount = 0L

    /**
     * Internal expire count (subset of misses that was caused by expire).
     */
    private var expireCount = 0L

    /**
     * Internal hit count.
     */
    private var hitCount = 0L


    private fun putNormalized(q: DnsMessage, result: DnsQueryResult) {
        backend[q] = DnsQueryResult(result.response)
    }


    private fun getNormalized(q: DnsMessage): DnsQueryResult? {


        val result = backend[q]

        if (result == null) {
            missCount++
            return null
        }

        val message = result.response

        // RFC 2181 § 5.2 says that all TTLs in a RRSet should be equal, if this isn't the case, then we assume the
        // shortest TTL to be the effective one.
        val answersMinTtl = message.answersMinTtl

        val expiryDate =
            message.receiveTimestamp.plus(answersMinTtl.toDuration(DurationUnit.SECONDS))
        val now = TimeSource.Monotonic.markNow()
        if (expiryDate < now) {
            missCount++
            expireCount++
            backend.remove(q)
            return null
        } else {
            hitCount++
            return result
        }

    }

    /**
     * Add an an dns answer/response for a given dns question. Implementations
     * should honor the ttl / receive timestamp.
     *
     * @param query  The query message containing a question.
     * @param result The DNS query result.
     */
    fun put(query: DnsMessage, result: DnsQueryResult) {
        putNormalized(query.asNormalizedVersion(), result)
    }

    /**
     * Request a cached dns response.
     *
     * @param query The query message containing a question.
     * @return The dns message.
     */
    fun get(query: DnsMessage): DnsQueryResult? {
        return getNormalized(query.asNormalizedVersion())
    }

}
