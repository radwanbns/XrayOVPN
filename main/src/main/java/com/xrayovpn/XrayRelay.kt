
package com.xrayovpn

import android.os.Build
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SNIHostName
import kotlin.concurrent.thread

enum class Mode(val label: String, val needsRelay: Boolean) {
    TCP("TCP", false),
    UDP("UDP", false),
    SSL("SSL", true),
    WS_PAYLOAD("WebSocket + Payload", true),
    SSL_PAYLOAD("SSL + WebSocket + Payload", true)
}

class XrayRelay(
    private val mode: Mode,
    private val localPort: Int,
    private val serverHost: String,
    private val serverPort: Int,
    private val sni: String,
    private val hostHeader: String,
    private val userAgent: String,
    private val payloadTemplate: String,
    private val onLog: (String) -> Unit = {}
) {
    @Volatile private var running = false
    private var server: ServerSocket? = null

    private val useTls =
        mode == Mode.SSL || mode == Mode.SSL_PAYLOAD

    private val useWebSocket =
        mode == Mode.WS_PAYLOAD || mode == Mode.SSL_PAYLOAD

    fun buildPayload(): String {
        return payloadTemplate
            .replace("[crlf]", "\r\n")
            .replace("[host]", hostHeader)
            .replace("[Host]", hostHeader)
            .replace("[ua]", userAgent)
            .replace("[port]", serverPort.toString())
    }

    fun start() {
        if (running) return
        running = true

        thread(name = "xray-accept") {
            try {
                val listener = ServerSocket(
                    localPort,
                    8,
                    InetAddress.getByName("127.0.0.1")
                )
                server = listener

                onLog("Relay started: 127.0.0.1:$localPort")

                while (running) {
                    val client = listener.accept()
                    thread(name = "xray-connection") {
                        handle(client)
                    }
                }
            } catch (e: Exception) {
                if (running) {
                    onLog("Relay error: ${e.message}")
                }
            }
        }
    }

    fun stop() {
        running = false
        try {
            server?.close()
        } catch (_: Exception) {
        }
        server = null
        onLog("Relay stopped")
    }

    private fun handle(client: Socket) {
        var remote: Socket? = null

        try {
            val plain = Socket()
            plain.connect(
                InetSocketAddress(serverHost, serverPort),
                15000
            )

            remote = if (useTls) {
                wrapTls(plain)
            } else {
                plain
            }

            if (useWebSocket) {
                performWebSocketHandshake(remote)

                onLog("WebSocket connected")

                runWebSocketTunnel(client, remote)
            } else {
                onLog("TCP/TLS connected")

                runRawTunnel(client, remote)
            }

        } catch (e: Exception) {
            onLog("Connection failed: ${e.message}")
        } finally {
            try {
                client.close()
            } catch (_: Exception) {
            }

            try {
                remote?.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun wrapTls(plain: Socket): Socket {
        val context = SSLContext.getInstance("TLS")
        context.init(null, null, null)

        val peerName = sni.ifBlank { serverHost }

        val ssl = context.socketFactory.createSocket(
            plain,
            peerName,
            serverPort,
            true
        ) as SSLSocket

        if (Build.VERSION.SDK_INT >= 24) {
            try {
                ssl.sslParameters = ssl.sslParameters.apply {
                    serverNames = listOf(SNIHostName(peerName))
                }
            } catch (e: Exception) {
                onLog("SNI warning: ${e.message}")
            }
        }

        ssl.startHandshake()
        return ssl
    }

    private fun performWebSocketHandshake(socket: Socket) {
        val keyBytes = ByteArray(16)
        SecureRandom().nextBytes(keyBytes)

        val key = Base64.getEncoder().encodeToString(keyBytes)

        var request = buildPayload()

        if (request.isBlank()) {
            request = "GET / HTTP/1.1\r\nHost: $hostHeader\r\n"
        }

        if (!request.contains("Sec-WebSocket-Key:", ignoreCase = true)) {
            request += "Sec-WebSocket-Key: $key\r\n"
        }

        if (!request.contains("Sec-WebSocket-Version:", ignoreCase = true)) {
            request += "Sec-WebSocket-Version: 13\r\n"
        }

        if (!request.contains("Upgrade:", ignoreCase = true)) {
            request += "Upgrade: websocket\r\n"
        }

        if (!request.contains("Connection:", ignoreCase = true)) {
            request += "Connection: Upgrade\r\n"
        }

        if (!request.endsWith("\r\n\r\n")) {
            request = request.trimEnd('\r', '\n') + "\r\n\r\n"
        }

        val output = socket.getOutputStream()
        output.write(request.toByteArray(Charsets.UTF_8))
        output.flush()

        val response = readHttpHeaders(socket.getInputStream())
        val status = response.lineSequence().firstOrNull().orEmpty()

        onLog("Server: $status")

        if (!status.contains(" 101 ")) {
            throw IOException("WebSocket upgrade rejected: $status")
        }

        val accept = response.lineSequence()
            .firstOrNull {
                it.startsWith("Sec-WebSocket-Accept:", ignoreCase = true)
            }
            ?.substringAfter(":")
            ?.trim()

        if (accept != null) {
            val expected = Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-1").digest(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
                        .toByteArray(Charsets.UTF_8)
                )
            )

            if (accept != expected) {
                throw IOException("Invalid WebSocket accept key")
            }
        }
    }

    private fun readHttpHeaders(input: InputStream): String {
        val result = StringBuilder()

        while (result.length < 16384) {
            val value = input.read()
            if (value == -1) {
                throw EOFException("Server closed during handshake")
            }

            result.append(value.toChar())

            if (result.endsWith("\r\n\r\n")) {
                return result.toString()
            }
        }

        throw IOException("HTTP headers too large")
    }

    private fun runRawTunnel(client: Socket, remote: Socket) {
        val up = thread {
            copyStream(
                client.getInputStream(),
                remote.getOutputStream()
            )
        }

        copyStream(
            remote.getInputStream(),
            client.getOutputStream()
        )

        try {
            up.join()
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun runWebSocketTunnel(client: Socket, remote: Socket) {
        val clientInput = client.getInputStream()
        val clientOutput = client.getOutputStream()

        val remoteInput = remote.getInputStream()
        val remoteOutput = remote.getOutputStream()

        val sender = thread(name = "ws-send") {
            try {
                val buffer = ByteArray(8192)

                while (running) {
                    val count = clientInput.read(buffer)
                    if (count < 0) break

                    writeWebSocketFrame(
                        remoteOutput,
                        0x2,
                        buffer,
                        count
                    )
                }
            } catch (_: Exception) {
            }
        }

        try {
            while (running) {
                val first = remoteInput.read()
                if (first < 0) break

                val second = remoteInput.read()
                if (second < 0) break

                val opcode = first and 0x0F
                val masked = (second and 0x80) != 0

                var length = (second and 0x7F).toLong()

                if (length == 126L) {
                    length = readUnsigned(remoteInput, 2)
                } else if (length == 127L) {
                    length = readUnsigned(remoteInput, 8)
                }

                if (length > 16L * 1024 * 1024) {
                    throw IOException("WebSocket frame too large")
                }

                val mask = if (masked) {
                    ByteArray(4).also { readFully(remoteInput, it) }
                } else {
                    null
                }

                val data = ByteArray(length.toInt())
                readFully(remoteInput, data)

                if (mask != null) {
                    for (i in data.indices) {
                        data[i] = (data[i].toInt() xor
                            mask[i % 4].toInt()).toByte()
                    }
                }

                when (opcode) {
                    0x0, 0x1, 0x2 -> {
                        clientOutput.write(data)
                        clientOutput.flush()
                    }

                    0x8 -> {
                        break
                    }

                    0x9 -> {
                        writeWebSocketFrame(
                            remoteOutput,
                            0xA,
                            data,
                            data.size
                        )
                    }

                    0xA -> {
                        // Pong received.
                    }
                }
            }
        } finally {
            try {
                client.close()
            } catch (_: Exception) {
            }

            try {
                remote.close()
            } catch (_: Exception) {
            }

            sender.interrupt()
        }
    }

    private fun writeWebSocketFrame(
        output: OutputStream,
        opcode: Int,
        data: ByteArray,
        length: Int
    ) {
        output.write(0x80 or (opcode and 0x0F))

        when {
            length < 126 -> {
                output.write(0x80 or length)
            }

            length <= 65535 -> {
                output.write(0x80 or 126)
                output.write((length shr 8) and 0xFF)
                output.write(length and 0xFF)
            }

            else -> {
                output.write(0x80 or 127)
                for (i in 7 downTo 0) {
                    output.write(
                        ((length.toLong() shr (i * 8)) and 0xFF).toInt()
                    )
                }
            }
        }

        val mask = ByteArray(4)
        SecureRandom().nextBytes(mask)
        output.write(mask)

        val maskedData = ByteArray(length)

        for (i in 0 until length) {
            maskedData[i] = (
                data[i].toInt() xor mask[i % 4].toInt()
            ).toByte()
        }

        output.write(maskedData)
        output.flush()
    }

    private fun readUnsigned(
        input: InputStream,
        bytes: Int
    ): Long {
        var result = 0L

        repeat(bytes) {
            val value = input.read()
            if (value < 0) throw EOFException()

            result = (result shl 8) or value.toLong()
        }

        return result
    }

    private fun readFully(
        input: InputStream,
        data: ByteArray
    ) {
        var offset = 0

        while (offset < data.size) {
            val count = input.read(data, offset, data.size - offset)
            if (count < 0) throw EOFException()

            offset += count
        }
    }

    private fun copyStream(
        input: InputStream,
        output: OutputStream
    ) {
        val buffer = ByteArray(16 * 1024)

        try {
            while (running) {
                val count = input.read(buffer)
                if (count < 0) break

                output.write(buffer, 0, count)
                output.flush()
            }
        } catch (_: IOException) {
        }
    }
}
