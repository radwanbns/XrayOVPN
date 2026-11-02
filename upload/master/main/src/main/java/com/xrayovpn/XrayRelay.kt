package com.xrayovpn

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread

enum class Mode(val label: String, val needsRelay: Boolean) {
    TCP("TCP", false),
    UDP("UDP", false),
    SSL("SSL", true),
    WS_PAYLOAD("WebSocket + Payload", true),
    SSL_PAYLOAD("SSL + Payload", true),
}

/**
 * Local relay. OpenVPN connects (TCP) to 127.0.0.1:localPort.
 * The relay connects to the real server, optionally wraps the link in TLS
 * (with a custom SNI) and/or sends the HTTP payload first, then pipes raw bytes.
 */
class XrayRelay(
    private val mode: Mode,
    private val localPort: Int,
    private val serverHost: String,
    private val serverPort: Int,
    private val sni: String,
    private val hostHeader: String,
    private val userAgent: String,
    private val payloadTemplate: String,
    private val onLog: (String) -> Unit = {},
) {
    @Volatile private var running = false
    private var server: ServerSocket? = null

    private val useTls = mode == Mode.SSL || mode == Mode.SSL_PAYLOAD
    private val usePayload = mode == Mode.WS_PAYLOAD || mode == Mode.SSL_PAYLOAD

    fun buildPayload(): String = payloadTemplate
        .replace("[crlf]", "\r\n")
        .replace("[host]", hostHeader)
        .replace("[ua]", userAgent)

    fun start() {
        running = true
        thread(name = "xray-accept") {
            try {
                server = ServerSocket(localPort, 8, InetAddress.getByName("127.0.0.1"))
                onLog("Relay on 127.0.0.1:$localPort (${mode.label})")
                while (running) {
                    val client = server!!.accept()
                    thread(name = "xray-conn") { handle(client) }
                }
            } catch (e: IOException) {
                if (running) onLog("Relay error: ${e.message}")
            }
        }
    }

    fun stop() {
        running = false
        try { server?.close() } catch (_: IOException) {}
    }

    private fun handle(client: Socket) {
        var remote: Socket? = null
        try {
            val plain = Socket()
            plain.connect(InetSocketAddress(serverHost, serverPort), 10_000)
            remote = if (useTls) wrapTls(plain) else plain

            if (usePayload) {
                remote.getOutputStream().apply { write(buildPayload().toByteArray()); flush() }
                val status = readHeaders(remote.getInputStream())
                onLog("Server: $status")
                if (!(status.contains(" 101") || status.contains(" 200"))) return
            }
            val r = remote
            val up = thread { pipe(client.getInputStream(), r.getOutputStream()) }
            pipe(r.getInputStream(), client.getOutputStream())
            up.join()
        } catch (e: Exception) {
            onLog("Connection failed: ${e.message}")
        } finally {
            try { client.close() } catch (_: IOException) {}
            try { remote?.close() } catch (_: IOException) {}
        }
    }

    // The outer TLS layer is not verified on purpose (custom SNI setups);
    // OpenVPN's own TLS inside the tunnel authenticates the server.
    private fun wrapTls(plain: Socket): Socket {
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf<TrustManager>(TrustAll), null)
        val name = sni.ifEmpty { serverHost }
        val s = ctx.socketFactory.createSocket(plain, name, serverPort, true) as javax.net.ssl.SSLSocket
        s.startHandshake()
        return s
    }

    // Byte by byte so no tunnel data is consumed after the end of the headers.
    private fun readHeaders(input: InputStream): String {
        val sb = StringBuilder()
        while (!sb.endsWith("\r\n\r\n")) {
            val b = input.read()
            if (b == -1 || sb.length > 8192) break
            sb.append(b.toChar())
        }
        return sb.lineSequence().firstOrNull().orEmpty()
    }

    private fun pipe(input: InputStream, output: OutputStream) {
        val buf = ByteArray(16 * 1024)
        try {
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                output.write(buf, 0, n)
                output.flush()
            }
        } catch (_: IOException) {}
    }

    private object TrustAll : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
}
