package io.github.remmerw.frey;


import java.net.ConnectException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;


public final class DnsResolver {
    public static final Set<Inet4Address> STATIC_IPV4_DNS_SERVERS = new CopyOnWriteArraySet<>();
    public static final Set<Inet6Address> STATIC_IPV6_DNS_SERVERS = new CopyOnWriteArraySet<>();
    private static final String DNS_ADDR = "dnsaddr=";
    private static final String DNS_LINK = "dnslink=";

    static {
        try {
            STATIC_IPV4_DNS_SERVERS.add(DnsUtility.ipv4From("8.8.8.8"));
            // CLOUDFLARE_DNS_SERVER_IP4 = "1.1.1.1";
        } catch (IllegalArgumentException e) {
            // todo LogUtils.error(TAG, "Could not add static IPv4 DNS Server " + e.getMessage());
        }

        try {
            STATIC_IPV6_DNS_SERVERS.add(DnsUtility.ipv6From("[2001:4860:4860::8888]"));
        } catch (IllegalArgumentException e) {
            // todo LogUtils.error(TAG, "Could not add static IPv6 DNS Server " + e.getMessage());
        }
    }

    private final DnsClient dnsClient = new DnsClient(() -> {
        ArrayList<InetAddress> list = new ArrayList<>();
        list.addAll(DnsResolver.STATIC_IPV4_DNS_SERVERS);
        list.addAll(DnsResolver.STATIC_IPV6_DNS_SERVERS);
        return list;
    }, new DnsCache());

    public DnsResolver() {
    }

    private Set<String> retrieveTxtRecords(String host) {
        Set<String> txtRecords = new HashSet<>();
        try {
            DnsQueryResult result = dnsClient.query(host, DnsRecord.TYPE.TXT);
            DnsMessage response = result.getResponse();
            for (DnsRecord dnsRecord : response.answerSection()) {
                DnsData payload = dnsRecord.getPayload();
                if (payload instanceof DnsData.TXT text) {
                    txtRecords.add(text.getText());
                } else {
                    // todo LogUtils.warning(TAG, payload.toString());
                }
            }
        } catch (ConnectException ignoreConnectException) {
            // nothing to do here
        } catch (Throwable throwable) {
            // todo   LogUtils.error(TAG, host + " " + throwable.getClass().getName());
        }
        return txtRecords;
    }

    public String resolveDnsLink(String host) {

        Set<String> txtRecords = retrieveTxtRecords("_dnslink.".concat(host));
        for (String txtRecord : txtRecords) {
            if (txtRecord.startsWith(DNS_LINK)) {
                return txtRecord.replaceFirst(DNS_LINK, "");
            }
        }
        return "";
    }

    public Set<String> resolveDnsAddr(String host) {
        return resolveDnsAddrHost(host, new HashSet<>());

    }


    private Set<String> resolveDnsAddrHost(String host, Set<String> hosts) {
        Set<String> multiAddresses = new HashSet<>();
        // recursion protection
        if (hosts.contains(host)) {
            return multiAddresses;
        }
        hosts.add(host);

        Set<String> txtRecords = retrieveTxtRecords("_dnsaddr." + host);

        for (String txtRecord : txtRecords) {
            try {
                if (txtRecord.startsWith(DNS_ADDR)) {
                    String testRecordReduced = txtRecord.replaceFirst(DNS_ADDR, "");
                    multiAddresses.add(testRecordReduced);
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
            } catch (Throwable throwable) {
                // todo (TAG, "Not supported " + txtRecord);
            }
        }
        return multiAddresses;
    }


}

