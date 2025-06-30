package io.github.remmerw.frey

import java.util.concurrent.locks.ReentrantLock
import kotlin.math.min


/**
 * Cache for DNS Entries. Implementations must be thread safe.
 */
internal class DnsCache {
    /**
     * The backend cache.
     */
    private val backend: LinkedHashMap<DnsMessage?, DnsQueryResult?>
    private val reentrantLock = ReentrantLock()

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


    init {
        backend = DnsMessageDnsQueryResultLinkedHashMap()
    }


    private fun putNormalized(q: DnsMessage?, result: DnsQueryResult) {
        if (result.response.receiveTimestamp <= 0L) {
            return
        }
        reentrantLock.lock()
        try {
            backend.put(q, DnsQueryResult(result.response))
        } finally {
            reentrantLock.unlock()
        }
    }


    private fun getNormalized(q: DnsMessage?): DnsQueryResult? {
        reentrantLock.lock()
        try {
            val result = backend.get(q)

            if (result == null) {
                missCount++
                return null
            }

            val message = result.response

            // RFC 2181 § 5.2 says that all TTLs in a RRSet should be equal, if this isn't the case, then we assume the
            // shortest TTL to be the effective one.
            val answersMinTtl = message.answersMinTtl

            val expiryDate = message.receiveTimestamp + (answersMinTtl * 1000)
            val now = System.currentTimeMillis()
            if (expiryDate < now) {
                missCount++
                expireCount++
                backend.remove(q)
                return null
            } else {
                hitCount++
                return result
            }
        } finally {
            reentrantLock.unlock()
        }
    }


    override fun toString(): String {
        return "DnsCache{usage=" + backend.size + "/" + capacity + ", hits=" + hitCount +
                ", misses=" + missCount + ", expires=" + expireCount + "}"
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

    private class DnsMessageDnsQueryResultLinkedHashMap :
        LinkedHashMap<DnsMessage?, DnsQueryResult?>(
            min(capacity + (capacity + 3) / 4 + 2, 11), 0.75f, true
        ) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<DnsMessage?, DnsQueryResult?>?): Boolean {
            return size > capacity
        }
    }

    companion object {
        /**
         * The internal capacity of the backend cache.
         */
        private const val capacity = 128
    }
}
