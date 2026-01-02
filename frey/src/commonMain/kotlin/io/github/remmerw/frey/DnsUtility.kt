package io.github.remmerw.frey

import io.github.remmerw.frey.DnsName.Companion.root
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress

object DnsUtility {

    const val UDP_PAYLOAD_SIZE: Int = 1024

    fun query(message: DnsMessage, address: InetSocketAddress): DnsQueryResult {
        return DnsQueryResult(queryUdp(message, address))
    }

    private fun asDatagram(query: DnsMessage, address: InetSocketAddress): DatagramPacket {
        val bytes = query.serialize()
        val data = bytes.readByteArray()
        return DatagramPacket(data, data.size, address)
    }

    private fun queryUdp(
        query: DnsMessage,
        address: InetSocketAddress
    ): DnsMessage {

        val packet = asDatagram(query, address)

        val socket = DatagramSocket()
        socket.soTimeout = SO_TIMEOUT
        try {
            socket.send(packet)

            val data = ByteArray(UDP_PAYLOAD_SIZE)
            val receivedPacket = DatagramPacket(data, data.size)

            socket.receive(receivedPacket)

            val buffer = Buffer()
            buffer.write(
                receivedPacket.data.copyOfRange(
                    0, receivedPacket.length
                )
            )

            val dnsMessage: DnsMessage = DnsMessage.parse(buffer)
            check(dnsMessage.id == query.id) {
                "The response's ID doesn't matches the request ID"
            }
            return dnsMessage

        } finally {
            socket.close()
        }
    }


    fun toASCII(input: String): String {
        // Special case if input is ".", i.e. a string containing only a single dot character. This is a workaround for
        // IDN.toASCII() implementations throwing an IllegalArgumentException on this input string (for example Android
        // APIs level 26, see https://issuetracker.google.com/issues/113070416).
        if (root().ace == input) {
            return root().ace
        }

        return input
    }
}
