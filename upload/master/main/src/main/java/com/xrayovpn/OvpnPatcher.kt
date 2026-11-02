package com.xrayovpn

/** Rewrites `proto` and `remote` lines of a .ovpn text according to the chosen mode. */
object OvpnPatcher {
    private val remoteRe = Regex("""^[ \t]*remote[ \t]+(\S+)(?:[ \t]+(\d+))?(?:[ \t]+\S+)?[ \t]*$""", RegexOption.MULTILINE)
    private val protoRe = Regex("""^[ \t]*proto[ \t]+\S+[ \t]*$""", RegexOption.MULTILINE)

    /** First `remote` line: host and port (default 1194). */
    fun parseRemote(config: String): Pair<String, Int>? {
        val m = remoteRe.find(config.replace("\r\n", "\n")) ?: return null
        return m.groupValues[1] to (m.groupValues[2].toIntOrNull() ?: 1194)
    }

    fun patch(config: String, mode: Mode, localPort: Int): String {
        var out = config.replace("\r\n", "\n")
        out = protoRe.replace(out, "")
        val head = StringBuilder()
        if (mode.needsRelay) {
            out = remoteRe.replace(out, "")
            head.append("proto tcp\n")
            head.append("remote 127.0.0.1 $localPort\n")
        } else {
            out = remoteRe.replace(out) { m ->
                "remote ${m.groupValues[1]} ${m.groupValues[2].ifEmpty { "1194" }}"
            }
            head.append(if (mode == Mode.UDP) "proto udp\n" else "proto tcp\n")
        }
        return head.toString() + out
    }
}
