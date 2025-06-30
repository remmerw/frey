package io.github.remmerw.frey;

import java.io.IOException;
import java.net.InetAddress;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;


/**
 * A minimal DNS client for TXT lookups, with IDN support.
 * This circumvents the missing javax.naming package on android.
 */
public final class DnsClient {


    /**
     * The internal random class for sequence generation.
     */
    private final Random random;

    /**
     * The internal DNS cache.
     */
    private final DnsCache dnsCache;

    private final Set<InetAddress> nonRaServers =
            Collections.newSetFromMap(new ConcurrentHashMap<>(4));
    private final Supplier<List<InetAddress>> settingSupplier;

    /**
     * Create a new DNS client with the given DNS cache.
     *
     * @param dnsCache The backend DNS cache.
     */
    DnsClient(Supplier<List<InetAddress>> settingSupplier, DnsCache dnsCache) {
        this.settingSupplier = settingSupplier;

        Random random;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e1) {
            random = new SecureRandom();
        }
        this.random = random;
        this.dnsCache = dnsCache;
    }

    /**
     * Whether a response from the DNS system should be cached or not.
     *
     * @param q      The question the response message should answer.
     * @param result The DNS query result.
     * @return True, if the response should be cached, false otherwise.
     */
    private static boolean isResponseCacheable(DnsQuestion q, DnsQueryResult result) {
        DnsMessage dnsMessage = result.getResponse();
        for (DnsRecord dnsRecord : dnsMessage.answerSection()) {
            if (dnsRecord.isAnswer(q)) {
                return true;
            }
        }
        return false;
    }

    private static DnsMessage.Builder newQuestion(DnsMessage.Builder message) {
        message.setRecursionDesired();
        boolean askForDnssec = false;
        message.getEdnsBuilder().setUdpPayloadSize(DnsUtility.UDP_PAYLOAD_SIZE).setDnssecOk(askForDnssec);
        return message;
    }

    public void onResponse(DnsMessage requestMessage, DnsQueryResult responseMessage) {
        final DnsQuestion q = requestMessage.getQuestion();
        if (isResponseCacheable(q, responseMessage)) {
            dnsCache.put(requestMessage.asNormalizedVersion(), responseMessage);
        }
    }

    /**
     * Query the system nameservers for a single entry of the class IN
     * (which is used for MX, SRV, A, AAAA and most other RRs).
     *
     * @param name The DNS name to request.
     * @param type The DNS type to request (SRV, A, AAAA, ...).
     * @return The response (or null on timeout/error).
     * @throws IOException if an IO error occurs.
     */
    public DnsQueryResult query(CharSequence name, DnsRecord.TYPE type) throws IOException {
        DnsQuestion q = DnsQuestion.create(DnsName.from(name), type);
        return query(q);
    }

    private DnsQueryResult query(DnsQuestion q) throws IOException {
        DnsMessage.Builder query = buildMessage(q);
        return query(query);
    }

    /**
     * Builds a {@link DnsMessage} object carrying the given Question.
     *
     * @param question {@link DnsQuestion} to be put in the DNS request.
     * @return A {@link DnsMessage} requesting the answer for the given Question.
     */
    private DnsMessage.Builder buildMessage(DnsQuestion question) {
        DnsMessage.Builder message = DnsMessage.builder();
        message.setQuestion(question);
        message.setId(random.nextInt());
        newQuestion(message);
        return message;
    }

    private DnsQueryResult query(DnsMessage query, InetAddress address) throws IOException {
        DnsQueryResult responseMessage = DnsUtility.query(query, address);
        onResponse(query, responseMessage);
        return responseMessage;
    }

    private List<InetAddress> getServerAddresses() {
        return settingSupplier.get();
    }

    private DnsQueryResult query(DnsMessage.Builder queryBuilder) throws IOException {
        DnsMessage q = newQuestion(queryBuilder).build();
        // While this query method does in fact re-use query(Question, String)
        // we still do a cache lookup here in order to avoid unnecessary
        // findDNS()calls, which are expensive on Android. Note that we do not
        // put the results back into the Cache, as this is already done by
        // query(Question, String).
        DnsQueryResult dnsQueryResult = dnsCache.get(q);
        if (dnsQueryResult != null) {
            return dnsQueryResult;
        }

        List<InetAddress> dnsServerAddresses = getServerAddresses();

        IOException ioException = null;
        for (InetAddress dns : dnsServerAddresses) {
            if (nonRaServers.contains(dns)) {
                // todo LogUtils.error(TAG, "Skipping " + dns + " because it was marked as \"recursion not available\"");
                continue;
            }

            try {
                dnsQueryResult = query(q, dns);
            } catch (IOException exception) {
                ioException = exception;
                continue;
            }

            DnsMessage responseMessage = dnsQueryResult.getResponse();
            if (!responseMessage.recursionAvailable()) {
                boolean newRaServer = nonRaServers.add(dns);
                if (newRaServer) {
                    /* TODO
                    LogUtils.error(TAG, "The DNS server " + dns
                            + " returned a response without the \"recursion available\" (RA) flag " +
                            "set. This likely indicates a misconfiguration because the " +
                            "server is not suitable for DNS resolution");*/
                }
                continue;
            }

            switch (responseMessage.responseCode()) {
                case NO_ERROR:
                case NX_DOMAIN:
                    break;
                default:
                    String warning = "Response from " + dns + " asked for " + q.getQuestion() +
                            " with error code: " + responseMessage.responseCode() + '.';
                    // todo LogUtils.error(TAG, warning);
            }

            return dnsQueryResult;
        }

        if (ioException != null) {
            throw ioException;
        }

        throw new IllegalArgumentException("No DNS server could be queried");
    }

}
