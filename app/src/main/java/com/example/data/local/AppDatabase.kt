package com.example.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.sqlite.db.SupportSQLiteDatabase
import com.example.data.local.dao.VpnProfileDao
import com.example.data.local.entity.VpnProfileEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

@Database(entities = [VpnProfileEntity::class], version = 5, exportSchema = false)
abstract class AppDatabase : RoomDatabase() {
    abstract fun vpnProfileDao(): VpnProfileDao

    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun getInstance(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "v2tunnel_vpn.db"
                )
                .fallbackToDestructiveMigration()
                .addCallback(object : Callback() {
                    override fun onCreate(db: SupportSQLiteDatabase) {
                        super.onCreate(db)
                        CoroutineScope(Dispatchers.IO).launch {
                            getInstance(context).vpnProfileDao().insertProfiles(getPrepopulatedProfiles())
                        }
                    }
                }).build()
                INSTANCE = instance
                instance
            }
        }

        private fun getPrepopulatedProfiles(): List<VpnProfileEntity> {
            return listOf(
                VpnProfileEntity(
                    id = 1L,
                    name = "🇸🇬 SG-01 Trojan HighSpeed (Direct/WS)",
                    protocol = "TROJAN",
                    server = "sg01.v2tunnel.net",
                    port = 443,
                    password = "trojan-secure-fast-pass",
                    network = "ws",
                    security = "tls",
                    sni = "sg01.v2tunnel.net",
                    path = "/trojan-ws",
                    host = "sg01.v2tunnel.net",
                    countryCode = "SG",
                    lastPingMs = 38,
                    isPreset = true,
                    isFavorite = true,
                    rawUri = "trojan://trojan-secure-fast-pass@sg01.v2tunnel.net:443?security=tls&type=ws&sni=sg01.v2tunnel.net&path=%2Ftrojan-ws#🇸🇬 SG-01 Trojan HighSpeed"
                ),
                VpnProfileEntity(
                    id = 2L,
                    name = "🇮🇩 ID-01 Xray VLESS Reality (Telkomsel/Indosat)",
                    protocol = "VLESS",
                    server = "id-xray.v2tunnel.net",
                    port = 443,
                    password = "e9a3b8d1-419a-4c40-9e0c-99c53f3e7a12",
                    network = "ws",
                    security = "tls",
                    sni = "vless-id.speed.cloudflare.com",
                    path = "/vless-ws",
                    host = "vless-id.speed.cloudflare.com",
                    countryCode = "ID",
                    lastPingMs = 24,
                    isPreset = true,
                    isFavorite = true,
                    rawUri = "vless://e9a3b8d1-419a-4c40-9e0c-99c53f3e7a12@id-xray.v2tunnel.net:443?type=ws&security=tls&sni=vless-id.speed.cloudflare.com&path=%2Fvless-ws#🇮🇩 ID-01 Xray VLESS Reality"
                ),
                VpnProfileEntity(
                    id = 3L,
                    name = "🇸🇬 SG-02 VMess CDN Cloudflare (WebSocket)",
                    protocol = "VMESS",
                    server = "104.21.56.88",
                    port = 443,
                    password = "c7d2e1f4-90a8-43e5-8271-bf6308da5e91",
                    method = "auto",
                    network = "ws",
                    security = "tls",
                    sni = "sg02-cdn.v2tunnel.net",
                    path = "/vmess-grpc",
                    host = "sg02-cdn.v2tunnel.net",
                    countryCode = "SG",
                    lastPingMs = 45,
                    isPreset = true,
                    isFavorite = false,
                    rawUri = "vmess://eyJhZGQiOiIxMDQuMjEuNTYuODgiLCJhaWQiOjAsImhvc3QiOiJzZzAyLWNkbi52MnR1bm5lbC5uZXQiLCJpZCI6ImM3ZDJlMWY0LTkwYTgtNDNlNS04MjcxLWJmNjMwOGRhNWU5MSIsIm5ldCI6IndzIiwicGF0aCI6Ii92bWVzcy1ncnBjIiwicG9ydCI6NDQzLCJwcyI6IvCfh7jwn4etIFNHLTAyIFZNZXNzIENETiIsInNjeSI6ImF1dG8iLCJzbmkiOiJzZzAyLWNkbi52MnR1bm5lbC5uZXQiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoibm9uZSIsInYiOiIyIn0="
                ),
                VpnProfileEntity(
                    id = 4L,
                    name = "🇯🇵 JP-01 Shadowsocks AEAD Fast (Tokyo)",
                    protocol = "SHADOWSOCKS",
                    server = "jp-tokyo.v2tunnel.net",
                    port = 8388,
                    password = "ss-aead-secret-key-jp",
                    method = "chacha20-ietf-poly1305",
                    security = "none",
                    countryCode = "JP",
                    lastPingMs = 82,
                    isPreset = true,
                    isFavorite = false,
                    rawUri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzcz1hZWFkLXNlY3JldC1rZXktanBAdHlwZS52MnR1bm5lbC5uZXQ6ODM4OA==#🇯🇵 JP-01 Shadowsocks AEAD"
                ),
                VpnProfileEntity(
                    id = 5L,
                    name = "🇮🇩 ID-02 SSH Standard + TLS (Golden Profile)",
                    protocol = "SSH",
                    server = "prem.nikuvpn.biz.id",
                    port = 443,
                    sshUsername = "testione",
                    sshPassword = "password",
                    sni = "prem.nikuvpn.biz.id:443",
                    sshPayload = "GET /cdn-cgi/trace HTTP/1.1[crlf]Host: api.quipper.com[crlf]Connection: Keep-Alive[crlf][crlf]PATCH / HTTP/1.1[crlf]Host: [host]",
                    sshDirectSsl = true,
                    sshTransport = "STANDARD",
                    remoteProxyEnabled = true,
                    remoteProxyType = "HTTP",
                    remoteProxyHost = "ads.ruangguru.com",
                    remoteProxyPort = 443,
                    countryCode = "ID",
                    lastPingMs = 28,
                    isPreset = true,
                    isFavorite = false,
                    rawUri = "ssh://testione:password@prem.nikuvpn.biz.id:443?sni=prem.nikuvpn.biz.id:443&ssl=true&proxy=ads.ruangguru.com:443&transport=STANDARD#🇮🇩 ID-02 SSH Standard + TLS"
                ),
                VpnProfileEntity(
                    id = 6L,
                    name = "🇺🇸 US-01 Trojan Gaming & Streaming (Silicon Valley)",
                    protocol = "TROJAN",
                    server = "us-west.v2tunnel.net",
                    port = 443,
                    password = "trojan-us-pass-stream",
                    network = "ws",
                    security = "tls",
                    sni = "us-west.v2tunnel.net",
                    path = "/trojan-us",
                    host = "us-west.v2tunnel.net",
                    countryCode = "US",
                    lastPingMs = 175,
                    isPreset = true,
                    isFavorite = false,
                    rawUri = "trojan://trojan-us-pass-stream@us-west.v2tunnel.net:443?security=tls&type=ws&sni=us-west.v2tunnel.net&path=%2Ftrojan-us#🇺🇸 US-01 Trojan Gaming"
                )
            )
        }
    }
}
