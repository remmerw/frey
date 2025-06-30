package io.github.remmerw.frey;


import java.util.LinkedHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Cache for DNS Entries. Implementations must be thread safe.
 */
final class DnsCache {

    /**
     * The internal capacity of the backend cache.
     */
    private static final int capacity = 128;
    /**
     * The backend cache.
     */
    private final LinkedHashMap<DnsMessage, DnsQueryResult> backend;
    private final ReentrantLock reentrantLock = new ReentrantLock();

    /**
     * Internal miss count.
     */
    private long missCount = 0L;
    /**
     * Internal expire count (subset of misses that was caused by expire).
     */
    private long expireCount = 0L;
    /**
     * Internal hit count.
     */
    private long hitCount = 0L;


    DnsCache() {
        backend = new DnsMessageDnsQueryResultLinkedHashMap();
    }


    private void putNormalized(DnsMessage q, DnsQueryResult result) {

        if (result.getResponse().receiveTimestamp() <= 0L) {
            return;
        }
        reentrantLock.lock();
        try {
            backend.put(q, new DnsQueryResult(result.getResponse()));
        } finally {
            reentrantLock.unlock();
        }
    }


    private DnsQueryResult getNormalized(DnsMessage q) {
        reentrantLock.lock();
        try {
            DnsQueryResult result = backend.get(q);

            if (result == null) {
                missCount++;
                return null;
            }

            DnsMessage message = result.getResponse();

            // RFC 2181 § 5.2 says that all TTLs in a RRSet should be equal, if this isn't the case, then we assume the
            // shortest TTL to be the effective one.
            final long answersMinTtl = message.getAnswersMinTtl();

            final long expiryDate = message.receiveTimestamp() + (answersMinTtl * 1000);
            final long now = System.currentTimeMillis();
            if (expiryDate < now) {
                missCount++;
                expireCount++;
                backend.remove(q);
                return null;
            } else {
                hitCount++;
                return result;
            }
        } finally {
            reentrantLock.unlock();
        }
    }


    @Override
    public String toString() {
        return "DnsCache{usage=" + backend.size() + "/" + capacity + ", hits=" + hitCount +
                ", misses=" + missCount + ", expires=" + expireCount + "}";
    }

    /**
     * Add an an dns answer/response for a given dns question. Implementations
     * should honor the ttl / receive timestamp.
     *
     * @param query  The query message containing a question.
     * @param result The DNS query result.
     */
    void put(DnsMessage query, DnsQueryResult result) {
        putNormalized(query.asNormalizedVersion(), result);
    }

    /**
     * Request a cached dns response.
     *
     * @param query The query message containing a question.
     * @return The dns message.
     */
    DnsQueryResult get(DnsMessage query) {
        return getNormalized(query.asNormalizedVersion());
    }

    private static class DnsMessageDnsQueryResultLinkedHashMap extends LinkedHashMap<DnsMessage, DnsQueryResult> {
        public DnsMessageDnsQueryResultLinkedHashMap() {
            super(Math.min(DnsCache.capacity + (DnsCache.capacity + 3) / 4 + 2, 11), 0.75f, true);
        }

        @Override
        protected boolean removeEldestEntry(Entry<DnsMessage, DnsQueryResult> eldest) {
            return size() > capacity;
        }
    }
}
