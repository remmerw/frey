<div>
    <div>
        <img src="https://img.shields.io/maven-central/v/io.github.remmerw/frey" alt="Kotlin Maven Version" />
        <img src="https://img.shields.io/badge/Platform-Android-brightgreen.svg?logo=android" alt="Badge Android" />
        <img src="https://img.shields.io/badge/Platform-JVM-8A2BE2.svg?logo=openjdk" alt="Badge JVM" />
    </div>
</div>

## Frey

The **Frey** project implements a DnsResolver client which based on [miniDns](https://github.com/MiniDNS/minidns).

## Integration

```
    
kotlin {
    sourceSets {
        commonMain.dependencies {
            ...
            implementation("io.github.remmerw:frey:0.2.2")
        }
        ...
    }
}
    
```

## API

```
    
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

```

