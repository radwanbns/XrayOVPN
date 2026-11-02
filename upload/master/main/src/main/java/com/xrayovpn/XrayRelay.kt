package com.xrayovpn

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SNIHostName
import java.net.StandardSocketOptions
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Collections
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

enum class Mode(val label: String, val needsRelay: Boolean) {
    TCP("TCP", false),
    UDP("UDP", false),
    SSL("SSL", true),
    WS_PAYLOAD("WebSocket + Payload", true),
    SSL_PAYLOAD("SSL + WebSocket + Payload", true)
}

object XrayRelay {

    private const val LOCAL_PORT_DEFAULT = 11940
    private const val CONNECT_TIMEOUT = 7000
    private const val HANDSHAKE_TIMEOUT = 10000
    private const val MAX_HTTP_HEADER = 16384
    private const val MAX_FRAME_SIZE = 4 * 1024 * 1024

    private val autoPorts = listOf(443, 80, 8080, 2086)

    private val running = AtomicBoolean(false)

    private val activeSockets =
        Collections.newSetFromMap(
            ConcurrentHashMap<Socket, Boolean>()
        )

    @Volatile
    private var listener: ServerSocket? = null

    @Volatile
    private var selectedPort: Int = -1

    private val random = SecureRandom()

    fun start(
        serverHost: String,
        serverPort: Int,
        mode: Mode,
        sni: String,
        hostHeader: String,
        payload: String,
        localPort: Int = LOCAL_PORT_DEFAULT
    ) {

        require(serverHost.isNotBlank()) {
            "Server address is empty"
        }

        require(localPort in 1..65535) {
            "Invalid local port"
        }

        stop()

        selectedPort = -1
        running.set(true)

        try {
            val server = ServerSocket()
            server.reuseAddress = true
            server.bind(
                InetSocketAddress("127.0.0.1", localPort)
            )

            listener = server

            Thread {
                acceptLoop(
                    server,
                    serverHost,
                    mode,
                    sni,
                    hostHeader,
                    payload
                )
            }.start()

        } catch (e: Exception) {
            running.set(false)
            throw IOException(
                "Cannot start local relay: ${e.message}",
                e
            )
        }
    }

    fun stop() {
        running.set(false)

        try {
            listener?.close()
        } catch (_: Exception) {
        }

        listener = null

        activeSockets.toList().forEach {
            closeSocket(it)
        }

        activeSockets.clear()
        selectedPort = -1
    }

    private fun acceptLoop(
        server: ServerSocket,
        serverHost: String,
        mode: Mode,
        sni: String,
        hostHeader: String,
        payload: String
    ) {

        while (running.get()) {

            try {
                val client = server.accept()

                activeSockets.add(client)

                Thread {
                    handleClient(
                        client,
                        serverHost,
                        mode,
                        sni,
                        hostHeader,
                        payload
                    )
                }.start()

            } catch (e: Exception) {
                if (running.get()) {
                    e.printStackTrace()
                }
            }
        }
    }

    private fun handleClient(
        client: Socket,
        serverHost: String,
        mode: Mode,
        sni: String,
        hostHeader: String,
        payload: String
    ) {

        var upstream: Socket? = null

        try {
            upstream = connectAutomatically(
                serverHost,
                mode,
                sni,
                hostHeader,
                payload
            )

            activeSockets.add(upstream)

            if (!running.get()) {
                return
            }

            relayTraffic(client, upstream)

        } catch (e: Exception) {
            e.printStackTrace()

        } finally {
            closeSocket(client)

            upstream?.let {
                closeSocket(it)
            }
        }
    }

    private fun connectAutomatically(
        serverHost: String,
        mode: Mode,
        sni: String,
        hostHeader: String,
        payload: String
    ): Socket {

        val ports = when (mode) {
            Mode.SSL -> listOf(443)
            else -> {
                val preferred = selectedPort
                if (preferred in autoPorts) {
                    listOf(preferred) + autoPorts.filter {
                        it != preferred
                    }
                } else {
                    autoPorts
                }
            }
        }

        var lastError: Exception? = null

        for (port in ports) {

            if (!running.get()) {
                throw IOException("Relay stopped")
            }

            var socket: Socket? = null

            try {
                val useTls = when (mode) {
                    Mode.SSL -> true
                    Mode.SSL_PAYLOAD -> port == 443
                    Mode.WS_PAYLOAD -> port == 443
                    else -> false
                }

                val rawSocket = Socket()

                socket = rawSocket

                rawSocket.tcpNoDelay = true

                rawSocket.connect(
                    InetSocketAddress(serverHost, port),
                    CONNECT_TIMEOUT
                )

                rawSocket.soTimeout = HANDSHAKE_TIMEOUT

                val connection = if (useTls) {
                    createTlsSocket(
                        rawSocket,
                        sni,
                        hostHeader,
                        serverHost,
                        port
                    )
                } else {
                    rawSocket
                }

                socket = connection

                if (mode != Mode.SSL) {
                    performWebSocketHandshake(
                        connection,
                        serverHost,
                        port,
                        hostHeader,
                        payload
                    )
                }

                connection.soTimeout = 0

                selectedPort = port

                return connection

            } catch (e: Exception) {

                lastError = e

                socket?.let {
                    closeSocket(it)
                }
            }
        }

        throw IOException(
            "All Cloudflare ports failed: ${lastError?.message}",
            lastError
        )
    }

    private fun createTlsSocket(
        raw: Socket,
        sni: String,
        hostHeader: String,
        serverHost: String,
        port: Int
    ): SSLSocket {

        val tlsHost = when {
            sni.isNotBlank() -> sni.trim()
            hostHeader.isNotBlank() -> hostHeader.trim()
                .substringBefore(":")
            else -> serverHost
        }

        val factory =
            SSLSocketFactory.getDefault() as SSLSocketFactory

        val ssl = factory.createSocket(
            raw,
            tlsHost,
            port,
            true
        ) as SSLSocket

        val parameters: SSLParameters = ssl.sslParameters

        parameters.endpointIdentificationAlgorithm = "HTTPS"

        if (!isIpAddress(tlsHost)) {
            parameters.serverNames = listOf(
                SNIHostName(tlsHost)
            )
        }

        ssl.sslParameters = parameters

        ssl.soTimeout = HANDSHAKE_TIMEOUT

        ssl.startHandshake()

        return ssl
    }

    private fun isIpAddress(host: String): Boolean {
        return host.matches(
            Regex("""\d{1,3}(\.\d{1,3}){3}""")
        ) || host.contains(":")
    }

    private fun performWebSocketHandshake(
        socket: Socket,
        serverHost: String,
        port: Int,
        hostHeader: String,
        payload: String
    ) {

        val keyBytes = ByteArray(16)
        random.nextBytes(keyBytes)

        val key = Base64.encodeToString(
            keyBytes,
            Base64.NO_WRAP
        )

        val actualHost = if (hostHeader.isNotBlank()) {
            hostHeader.trim()
        } else {
            serverHost
        }

        var request = payload
            .replace("[crlf]", "\r\n", true)
            .replace("[host]", actualHost, true)
            .replace("[port]", port.toString(), true)
            .replace("[ua]", "Xray-OVPN", true)

        request = request.trim()

        if (request.isEmpty()) {
            request = "GET / HTTP/1.1"
        }

        if (!request.contains("\r\n")) {
            request += "\r\n"
        }

        request = Regex(
            """(?im)^Sec-WebSocket-Key:.*$"""
        ).replace(request, "Sec-WebSocket-Key: $key")

        if (!Regex("""(?im)^Host:""").containsMatchIn(request)) {
            request += "\r\nHost: $actualHost"
        }

        if (!Regex("""(?im)^Upgrade:""").containsMatchIn(request)) {
            request += "\r\nUpgrade: websocket"
        }

        if (!Regex("""(?im)^Connection:""").containsMatchIn(request)) {
            request += "\r\nConnection: Upgrade"
        }

        if (!Regex("""(?im)^Sec-WebSocket-Key:""").containsMatchIn(request)) {
            request += "\r\nSec-WebSocket-Key: $key"
        }

        if (!Regex("""(?im)^Sec-WebSocket-Version:""").containsMatchIn(request)) {
            request += "\r\nSec-WebSocket-Version: 13"
        }

        if (!Regex("""(?im)^User-Agent:""").containsMatchIn(request)) {
            request += "\r\nUser-Agent: Xray-OVPN"
        }

        request = request.trimEnd('\r', '\n') + "\r\n\r\n"

        val output = socket.getOutputStream()

        output.write(request.toByteArray(Charsets.UTF_8))
        output.flush()

        val response = readHttpHeaders(socket)

        val statusLine = response
            .substringBefore("\r\n")
            .trim()

        if (!statusLine.contains("101")) {
            throw IOException(
                "WebSocket rejected: $statusLine"
            )
        }

        val expectedAccept = Base64.encodeToString(
            MessageDigest.getInstance("SHA-1").digest(
                (
                    key +
                    "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                ).toByteArray(Charsets.UTF_8)
            ),
            Base64.NO_WRAP
        )

        val acceptHeader = Regex(
            """(?im)^Sec-WebSocket-Accept:\s*(.+)$"""
        ).find(response)?.groupValues?.get(1)?.trim()

        if (acceptHeader != expectedAccept) {
            throw IOException(
                "Invalid WebSocket handshake"
            )
        }
    }

    private fun readHttpHeaders(socket: Socket): String {

        val input = socket.getInputStream()
        val buffer = ByteArrayOutputStream()

        var state = 0

        while (buffer.size() < MAX_HTTP_HEADER) {

            val value = input.read()

            if (value == -1) {
                throw EOFException(
                    "Server closed during WebSocket handshake"
                )
            }

            buffer.write(value)

            state = when {
                state == 0 && value == 13 -> 1
                state == 1 && value == 10 -> 2
                state == 2 && value == 13 -> 3
                state == 3 && value == 10 -> 4
                value == 13 -> 1
                else -> 0
            }

            if (state == 4) {
                return buffer.toString("UTF-8")
            }
        }

        throw IOException("HTTP response headers too large")
    }

    private fun relayTraffic(
        client: Socket,
        upstream: Socket
    ) {

        val closed = AtomicBoolean(false)

        fun shutdown() {
            if (closed.compareAndSet(false, true)) {
                closeSocket(client)
                closeSocket(upstream)
            }
        }

        val clientToServer = Thread {

            try {
                val input = client.getInputStream()
                val output = DataOutputStream(
                    upstream.getOutputStream()
                )

                val buffer = ByteArray(16384)

                while (!closed.get() && running.get()) {

                    val count = input.read(buffer)

                    if (count == -1) break

                    if (count > 0) {
                        writeWebSocketFrame(
                            output,
                            2,
                            buffer.copyOf(count)
                        )
                    }
                }

            } catch (_: Exception) {
            } finally {
                shutdown()
            }
        }

        val serverToClient = Thread {

            try {
                val input = DataInputStream(
                    upstream.getInputStream()
                )

                val output = client.getOutputStream()

                while (!closed.get() && running.get()) {

                    val frame = readWebSocketFrame(input)

                    when (frame.opcode) {

                        0, 2 -> {
                            output.write(frame.payload)
                            output.flush()
                        }

                        8 -> break

                        9 -> {
                            writeWebSocketFrame(
                                DataOutputStream(
                                    upstream.getOutputStream()
                                ),
                                10,
                                frame.payload
                            )
                        }

                        10 -> {
                            // Pong received.
                        }

                        else -> {
                            throw IOException(
                                "Unsupported WebSocket frame"
                            )
                        }
                    }
                }

            } catch (_: Exception) {
            } finally {
                shutdown()
            }
        }

        clientToServer.start()
        serverToClient.start()

        try {
            clientToServer.join()
            serverToClient.join()
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }

        shutdown()
    }

    private data class WebSocketFrame(
        val opcode: Int,
        val payload: ByteArray
    )

    private fun readWebSocketFrame(
        input: DataInputStream
    ): WebSocketFrame {

        val first = input.readUnsignedByte()
        val second = input.readUnsignedByte()

        val opcode = first and 0x0F
        val masked = (second and 0x80) != 0

        var length = (second and 0x7F).toLong()

        if (length == 126L) {
            length = input.readUnsignedShort().toLong()
        } else if (length == 127L) {

            length = input.readLong()

            if (length < 0) {
                throw IOException("Invalid frame length")
            }
        }

        if (length > MAX_FRAME_SIZE) {
            throw IOException("WebSocket frame too large")
        }

        val mask = if (masked) {
            ByteArray(4).also {
                input.readFully(it)
            }
        } else {
            null
        }

        val payload = ByteArray(length.toInt())

        input.readFully(payload)

        if (mask != null) {
            for (i in payload.indices) {
                payload[i] = (
                    payload[i].toInt() xor
                    mask[i % 4].toInt()
                ).toByte()
            }
        }

        return WebSocketFrame(opcode, payload)
    }

    private fun writeWebSocketFrame(
        output: DataOutputStream,
        opcode: Int,
        payload: ByteArray
    ) {

        val mask = ByteArray(4)
        random.nextBytes(mask)

        output.writeByte(0x80 or opcode)

        when {
            payload.size < 126 -> {
                output.writeByte(0x80 or payload.size)
            }

            payload.size <= 65535 -> {
                output.writeByte(0x80 or 126)
                output.writeShort(payload.size)
            }

            else -> {
                output.writeByte(0x80 or 127)
                output.writeLong(payload.size.toLong())
            }
        }

        output.write(mask)

        val maskedPayload = ByteArray(payload.size)

        for (i in payload.indices) {
            maskedPayload[i] = (
                payload[i].toInt() xor
                mask[i % 4].toInt()
            ).toByte()
        }

        output.write(maskedPayload)
        output.flush()
    }

    private fun closeSocket(socket: Socket) {
        try {
            socket.close()
        } catch (_: Exception) {
        }

        activeSockets.remove(socket)
    }
}
