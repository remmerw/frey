<div>
    <div>
        <img src="https://img.shields.io/maven-central/v/io.github.remmerw/frey" alt="Kotlin Maven Version" />
        <img src="https://img.shields.io/badge/Platform-Android-brightgreen.svg?logo=android" alt="Badge Android" />
        <img src="https://img.shields.io/badge/Platform-iOS%20%2F%20macOS-lightgrey.svg?logo=apple" alt="Badge iOS" />
        <img src="https://img.shields.io/badge/Platform-JVM-8A2BE2.svg?logo=openjdk" alt="Badge JVM" />
    </div>
</div>

## Frey

The **Frey** implements a DnsResolver which based on [miniDns](https://github.com/MiniDNS/minidns).

## Integration

```
    
kotlin {
    sourceSets {
        commonMain.dependencies {
            ...
            implementation("io.github.remmerw:frey:0.0.1")
        }
        ...
    }
}
    
```

## API

```

    @Test
    fun testTXTRecord() : Unit = runBlocking(Dispatchers.IO) {
        val resolver = DnsResolver()
        val result = resolver.retrieveTxtRecords("_dnsaddr.bootstrap.libp2p.io")
        assertNotNull(result)
        assertFalse(result.isEmpty())
        result.forEach { text -> println(text) }
    }

    @Test
    fun testAAAARecord() : Unit = runBlocking(Dispatchers.IO) {
        val resolver = DnsResolver()
        val addresses = resolver.retrieveAAAARecord("www.welt.de")
        assertNotNull(addresses)
        assertFalse(addresses.isEmpty())
    }

    @Test
    fun testARecord() : Unit = runBlocking(Dispatchers.IO) {
        val resolver = DnsResolver()
        val addresses = resolver.retrieveARecord("www.welt.de")
        assertNotNull(addresses)
        assertFalse(addresses.isEmpty())
    }
    
    @Test
    fun testDnsAddr() : Unit = runBlocking(Dispatchers.IO) {
        val resolver = DnsResolver()
        val result = resolver.resolveDnsAddr("bootstrap.libp2p.io")
        assertNotNull(result)
        assertFalse(result.isEmpty())
        result.forEach { text -> println(text) }
    }

    @Test
    fun testDnsLinkFailure() : Unit = runBlocking(Dispatchers.IO) {
        val resolver = DnsResolver()
        val result = resolver.resolveDnsLink("bootstrap.libp2p.io") // this fails, not valid
        assertNotNull(result)
        assertTrue(result.isEmpty())
    }

```

