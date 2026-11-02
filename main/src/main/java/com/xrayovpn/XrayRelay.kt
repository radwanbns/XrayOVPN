package com.xrayovpn

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.*
import de.blinkt.openvpn.core.ConfigParser
import de.blinkt.openvpn.core.ProfileManager
import java.io.StringReader

class XrayActivity : Activity() {

    private lateinit var ovpn: EditText
    private lateinit var status: TextView

    companion object {
        const val LOCAL_PORT = 11940
        const val PROFILE_NAME = "XrayOvpn"
        const val PICK = 42

        const val DEFAULT_PAYLOAD =
            "GET / HTTP/1.1[crlf]" +
            "Host: [host][crlf]" +
            "Connection: Upgrade[crlf]" +
            "User-Agent: [ua][crlf]" +
            "Upgrade: websocket[crlf][crlf]"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pad = (16 * resources.displayMetrics.density).toInt()

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }

        fun field(
            hintText: String,
            defaultText: String = "",
            lines: Int = 1
        ): EditText {
            return EditText(this).apply {
                hint = hintText
                setText(defaultText)

                if (lines > 1) {
                    minLines = lines
                    gravity = Gravity.TOP
                }

                root.addView(this)
            }
        }

        val title = TextView(this).apply {
            text = "Xray OVPN"
            textSize = 24f
        }
        root.addView(title)

        val spinner = Spinner(this)

        spinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            Mode.values().map { it.label }
        )

        root.addView(spinner)

        val open = Button(this).apply {
            text = "Open .ovpn file"
        }
        root.addView(open)

        ovpn = field(
            "Paste .ovpn configuration here",
            "",
            7
        )

        val sni = field("SNI / TLS Server Name")

        val host = field("WebSocket Host Header")

        val ua = field(
            "User-Agent",
            "Mozilla/5.0"
        )

        val payload = field(
            "WebSocket Payload",
            DEFAULT_PAYLOAD,
            4
        )

        val connect = Button(this).apply {
            text = "Connect"
        }
        root.addView(connect)

        val stop = Button(this).apply {
            text = "Stop"
        }
        root.addView(stop)

        status = TextView(this).apply {
            text = "Disconnected"
            textSize = 16f
        }
        root.addView(status)

        spinner.onItemSelectedListener =
            object : android.widget.AdapterView.OnItemSelectedListener {

                override fun onItemSelected(
                    parent: android.widget.AdapterView<*>?,
                    view: View?,
                    position: Int,
                    id: Long
                ) {
                    val mode = Mode.values()[position]

                    val usesTls =
                        mode == Mode.SSL ||
                        mode == Mode.SSL_PAYLOAD ||
                        mode == Mode.WS_PAYLOAD

                    val usesPayload =
                        mode == Mode.WS_PAYLOAD ||
                        mode == Mode.SSL_PAYLOAD

                    sni.visibility =
                        if (usesTls) View.VISIBLE else View.GONE

                    host.visibility =
                        if (usesPayload) View.VISIBLE else View.GONE

                    ua.visibility =
                        if (usesPayload) View.VISIBLE else View.GONE

                    payload.visibility =
                        if (usesPayload) View.VISIBLE else View.GONE
                }

                override fun onNothingSelected(
                    parent: android.widget.AdapterView<*>?
                ) {}
            }

        open.setOnClickListener {
            val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
                type = "*/*"
                addCategory(Intent.CATEGORY_OPENABLE)
            }

            startActivityForResult(intent, PICK)
        }

        connect.setOnClickListener {

            try {
                val mode = Mode.values()[
                    spinner.selectedItemPosition
                ]

                val config = ovpn.text.toString().trim()

                if (config.isEmpty()) {
                    status.text = "Please import an .ovpn configuration"
                    return@setOnClickListener
                }

                val remote = OvpnPatcher.parseRemote(config)

                if (remote == null) {
                    status.text = "No valid remote server found"
                    return@setOnClickListener
                }

                XrayRelay.stop()

                if (mode.needsRelay) {

                    val serverHost = remote.first

                    val serverPort = remote.second

                    val serverSni = sni.text.toString().trim()

                    val serverHostHeader =
                        host.text.toString().trim()

                    val userAgent =
                        ua.text.toString().trim()

                    val customPayload =
                        payload.text.toString()
                            .replace(
                                "[ua]",
                                userAgent,
                                ignoreCase = true
                            )

                    XrayRelay.start(
                        serverHost = serverHost,
                        serverPort = serverPort,
                        mode = mode,
                        sni = serverSni,
                        hostHeader = serverHostHeader,
                        payload = customPayload,
                        localPort = LOCAL_PORT
                    )

                    status.text =
                        "Relay started. Testing Cloudflare ports..."
                }

                val patchedConfig = OvpnPatcher.patch(
                    config,
                    mode,
                    LOCAL_PORT
                )

                startProfile(patchedConfig)

                status.text = "Connecting..."

            } catch (e: Exception) {

                XrayRelay.stop()

                status.text =
                    "Connection error: ${e.message}"
            }
        }

        stop.setOnClickListener {

            XrayRelay.stop()

            try {
                val intent = Intent().setClassName(
                    this,
                    "de.blinkt.openvpn.api.DisconnectVPN"
                )

                startActivity(intent)

                status.text = "Disconnected"

            } catch (e: Exception) {

                status.text =
                    "Disconnect using the VPN notification"
            }
        }

        setContentView(
            ScrollView(this).apply {
                addView(root)
            }
        )
    }

    private fun startProfile(configText: String) {

        val parser = ConfigParser()

        parser.parseConfig(StringReader(configText))

        val profile = parser.convertProfile()

        profile.mName = PROFILE_NAME

        // Keep the WebSocket relay outside the VPN tunnel.
        profile.mAllowedAppsVpn.add(packageName)
        profile.mAllowedAppsVpnAreDisallowed = true

        val manager = ProfileManager.getInstance(this)

        manager.getProfileByName(PROFILE_NAME)?.let {
            manager.removeProfile(this, it)
        }

        manager.addProfile(profile)

        ProfileManager.saveProfile(this, profile)

        manager.saveProfileList(this)

        try {

            val intent = Intent(Intent.ACTION_MAIN)

            intent.setClassName(
                this,
                "de.blinkt.openvpn.api.ConnectVPN"
            )

            intent.putExtra(
                "de.blinkt.openvpn.api.profileName",
                PROFILE_NAME
            )

            startActivity(intent)

        } catch (e: android.content.ActivityNotFoundException) {

            val intent = Intent(Intent.ACTION_MAIN)

            intent.setClassName(
                this,
                "de.blinkt.openvpn.LaunchVPN"
            )

            intent.putExtra(
                "de.blinkt.openvpn.shortcutProfileName",
                PROFILE_NAME
            )

            startActivity(intent)
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(
        requestCode: Int,
        resultCode: Int,
        data: Intent?
    ) {
        super.onActivityResult(
            requestCode,
            resultCode,
            data
        )

        if (
            requestCode == PICK &&
            resultCode == RESULT_OK
        ) {
            val uri = data?.data ?: return

            try {
                contentResolver.openInputStream(uri)?.use {
                    ovpn.setText(
                        it.readBytes().toString(Charsets.UTF_8)
                    )
                }

                status.text = "Configuration imported"

            } catch (e: Exception) {
                status.text =
                    "Import error: ${e.message}"
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // لا توقف Relay هنا حتى لا ينقطع الاتصال عند تدوير الشاشة.
    }
}
