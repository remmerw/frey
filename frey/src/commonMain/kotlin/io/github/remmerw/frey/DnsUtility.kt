package io.github.remmerw.frey

import io.github.remmerw.frey.DnsName.Companion.root
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.Datagram
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.readShort
import io.ktor.utils.io.writeBuffer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.io.Buffer

interface DnsUtility {
    companion object {

        suspend fun query(message: DnsMessage, address: InetSocketAddress): DnsQueryResult {
            try {
                return DnsQueryResult(queryUdp(message, address))
            } catch (_: Exception) {
                // ignore the first query
            }

            return DnsQueryResult(queryTcp(message, address))
        }

        private fun asDatagram(query: DnsMessage, address: InetSocketAddress): Datagram {
            val bytes = query.serialize()
            return Datagram(bytes, address)
        }

        private suspend fun queryUdp(
            query: DnsMessage,
            address: InetSocketAddress
        ): DnsMessage {
            var packet = asDatagram(query, address)

            val selectorManager = SelectorManager(Dispatchers.IO)

            try {
                aSocket(selectorManager).udp().connect(
                    address, null
                ).use { socket ->
                    socket.send(packet)
                    packet = socket.receive()
                    val dnsMessage: DnsMessage = DnsMessage.Companion.parse(packet.packet)
                    check(dnsMessage.id == query.id) { "The response's ID doesn't matches the request ID" }
                    return dnsMessage
                }
            } finally {
                selectorManager.close()
            }
        }


        private suspend fun queryTcp(message: DnsMessage, address: InetSocketAddress): DnsMessage {
            val selectorManager = SelectorManager(Dispatchers.IO)
            try {
                aSocket(selectorManager).tcp().connect(address) {
                    socketTimeout = DNS_TIMEOUT.toLong()
                }.use { socket ->

                    val sendChannel = socket.openWriteChannel(autoFlush = true)
                    val buffer = Buffer()
                    message.writeTo(buffer)
                    sendChannel.writeBuffer(buffer)

                    val receiveChannel = socket.openReadChannel()
                    val length = receiveChannel.readShort()
                    val data = receiveChannel.readBuffer(length.toInt())
                    val dnsMessage: DnsMessage = DnsMessage.Companion.parse(data)
                    check(dnsMessage.id == message.id) { "The response's ID doesn't matches the request ID" }
                    return dnsMessage
                }
            } finally {
                selectorManager.close()
            }
        }


        fun toASCII(input: String): String {
            // Special case if input is ".", i.e. a string containing only a single dot character. This is a workaround for
            // IDN.toASCII() implementations throwing an IllegalArgumentException on this input string (for example Android
            // APIs level 26, see https://issuetracker.google.com/issues/113070416).
            if (root().ace == input) {
                return root().ace
            }

            return input // todo IDN.toASCII(input) [not yet exists in kotlin]
        }

        const val UDP_PAYLOAD_SIZE: Int = 1024

        /**
         * DNS timeout.
         */
        const val DNS_TIMEOUT: Int = 5000 // 5000 ms
    }
}
