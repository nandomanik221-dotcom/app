package com.example.vpn.xray

import com.example.model.VpnProfile
import org.json.JSONArray
import org.json.JSONObject

/**
 * Generates an official, standard Xray-core / V2Ray JSON configuration
 * for VMess client outbound and local SOCKS5 inbound routing.
 */
object XrayVmessConfigBuilder {

    fun buildConfig(profile: VpnProfile, localSocksPort: Int = 10808, localHttpPort: Int = 10809): String {
        val root = JSONObject()

        // 1. Log configuration
        val log = JSONObject().apply {
            put("loglevel", "warning")
            put("access", "")
            put("error", "")
        }
        root.put("log", log)

        // 2. Inbounds (Local SOCKS5 and HTTP proxy for TUN router)
        val inbounds = JSONArray().apply {
            // SOCKS5 inbound
            put(JSONObject().apply {
                put("tag", "socks-in")
                put("port", localSocksPort)
                put("listen", "127.0.0.1")
                put("protocol", "socks")
                put("settings", JSONObject().apply {
                    put("auth", "noauth")
                    put("udp", true)
                    put("ip", "127.0.0.1")
                })
                put("sniffing", JSONObject().apply {
                    put("enabled", true)
                    put("destOverride", JSONArray().apply {
                        put("http")
                        put("tls")
                    })
                })
            })

            // HTTP inbound
            put(JSONObject().apply {
                put("tag", "http-in")
                put("port", localHttpPort)
                put("listen", "127.0.0.1")
                put("protocol", "http")
                put("settings", JSONObject().apply {
                    put("allowTransparent", false)
                })
            })
        }
        root.put("inbounds", inbounds)

        // 3. Outbound (VMess Server connection)
        val vnextUser = JSONObject().apply {
            put("id", profile.password.trim()) // VMess UUID
            put("alterId", 0)
            put("security", profile.method.ifBlank { "auto" })
            put("level", 8)
        }

        val vnextServer = JSONObject().apply {
            put("address", profile.server.trim())
            put("port", profile.port)
            put("users", JSONArray().apply { put(vnextUser) })
        }

        val vmessSettings = JSONObject().apply {
            put("vnext", JSONArray().apply { put(vnextServer) })
        }

        val streamSettings = JSONObject().apply {
            val netType = profile.network.lowercase().ifBlank { "ws" }
            put("network", netType)

            val isTls = profile.security.equals("tls", ignoreCase = true) || profile.port == 443
            put("security", if (isTls) "tls" else "none")

            if (isTls) {
                val effectiveSni = profile.sni.ifBlank { profile.host.ifBlank { profile.server } }
                put("tlsSettings", JSONObject().apply {
                    put("serverName", effectiveSni)
                    put("allowInsecure", false)
                })
            }

            when (netType) {
                "ws" -> {
                    put("wsSettings", JSONObject().apply {
                        put("path", profile.path.ifBlank { "/" })
                        val effectiveHost = profile.host.ifBlank { profile.sni.ifBlank { profile.server } }
                        put("headers", JSONObject().apply {
                            put("Host", effectiveHost)
                        })
                    })
                }
                "grpc" -> {
                    put("grpcSettings", JSONObject().apply {
                        put("serviceName", profile.path.removePrefix("/"))
                        put("multiMode", true)
                    })
                }
                "httpupgrade" -> {
                    put("httpupgradeSettings", JSONObject().apply {
                        put("path", profile.path.ifBlank { "/" })
                        put("host", profile.host.ifBlank { profile.server })
                    })
                }
                "tcp" -> {
                    if (profile.host.isNotBlank()) {
                        put("tcpSettings", JSONObject().apply {
                            put("header", JSONObject().apply {
                                put("type", "http")
                                put("request", JSONObject().apply {
                                    put("path", JSONArray().apply { put(profile.path.ifBlank { "/" }) })
                                    put("headers", JSONObject().apply {
                                        put("Host", JSONArray().apply { put(profile.host) })
                                    })
                                })
                            })
                        })
                    }
                }
            }
        }

        val outbounds = JSONArray().apply {
            // Primary VMess Outbound
            put(JSONObject().apply {
                put("tag", "proxy")
                put("protocol", "vmess")
                put("settings", vmessSettings)
                put("streamSettings", streamSettings)
                put("mux", JSONObject().apply {
                    put("enabled", false)
                    put("concurrency", 8)
                })
            })

            // Direct outbound for local bypass if needed
            put(JSONObject().apply {
                put("tag", "direct")
                put("protocol", "freedom")
                put("settings", JSONObject())
            })

            // Block outbound
            put(JSONObject().apply {
                put("tag", "block")
                put("protocol", "blackhole")
                put("settings", JSONObject().apply {
                    put("response", JSONObject().apply { put("type", "none") })
                })
            })
        }
        root.put("outbounds", outbounds)

        // 4. DNS Settings
        val dns = JSONObject().apply {
            put("servers", JSONArray().apply {
                put("1.1.1.1")
                put("8.8.8.8")
                put("localhost")
            })
        }
        root.put("dns", dns)

        // 5. Routing Rules
        val routing = JSONObject().apply {
            put("domainStrategy", "IPIfNonMatch")
            put("rules", JSONArray().apply {
                put(JSONObject().apply {
                    put("type", "field")
                    put("ip", JSONArray().apply {
                        put("geoip:private")
                    })
                    put("outboundTag", "direct")
                })
            })
        }
        root.put("routing", routing)

        return root.toString(2)
    }
}
