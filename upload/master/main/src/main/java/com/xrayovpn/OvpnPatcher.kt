
package com.xrayovpn

object OvpnPatcher {

    private val remoteRegex = Regex(
        """(?im)^[ \t]*remote[ \t]+(\S+)(?:[ \t]+(\d+))?(?:[ \t]+\S+)?[ \t]*(?:#.*)?$"""
    )

    private val protoRegex = Regex(
        """(?im)^[ \t]*proto[ \t]+\S+[ \t]*(?:#.*)?$"""
    )

    private val clientRegex = Regex(
        """(?im)^[ \t]*client[ \t]*(?:#.*)?\r?\n?"""
    )

    private val portRegex = Regex(
        """(?im)^[ \t]*port[ \t]+(\d+)[ \t]*(?:#.*)?$"""
    )

    fun parseRemote(config: String): Pair<String, Int>? {

        val normalized = config
            .replace("\r\n", "\n")
            .replace('\r', '\n')

        val match = remoteRegex.find(normalized)
            ?: return null

        val host = match.groupValues[1]

        val defaultPort = portRegex
            .find(normalized)
            ?.groupValues
            ?.get(1)
            ?.toIntOrNull()
            ?: 1194

        val port = match.groupValues[2]
            .toIntOrNull()
            ?: defaultPort

        if (host.isBlank() || port !in 1..65535) {
            return null
        }

        return Pair(host, port)
    }

    fun patch(
        config: String,
        mode: Mode,
        localPort: Int
    ): String {

        require(localPort in 1..65535) {
            "Invalid local port"
        }

        var output = config
            .replace("\r\n", "\n")
            .replace('\r', '\n')

        val protocol = when (mode) {
            Mode.UDP -> "udp"
            else -> "tcp-client"
        }

        if (mode.needsRelay) {

            // Route OpenVPN through the local WebSocket relay.
            output = remoteRegex.replace(output, "")

        } else {

            // Keep the original remote servers for direct mode.
            output = remoteRegex.replace(output) { match ->

                val host = match.groupValues[1]
                val port = match.groupValues[2]

                if (port.isEmpty()) {
                    "remote $host"
                } else {
                    "remote $host $port"
                }
            }
        }

        // Remove old protocol and client directives.
        output = protoRegex.replace(output, "")
        output = clientRegex.replace(output, "")

        val header = buildString {

            append("client\n")
            append("proto $protocol\n")

            if (mode.needsRelay) {
                append("remote 127.0.0.1 $localPort\n")
            }
        }

        return header + output.trimStart('\n')
    }
}
