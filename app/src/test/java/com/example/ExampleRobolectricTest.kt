package com.example

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.example.data.local.AppDatabase
import com.example.data.local.entity.VpnProfileEntity
import com.example.model.VpnProtocol
import com.example.parser.VpnConfigParser
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

  private lateinit var db: AppDatabase

  @Before
  fun createDb() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
      .allowMainThreadQueries()
      .build()
  }

  @After
  fun closeDb() {
    db.close()
  }

  @Test
  fun `read string from context`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val appName = context.getString(R.string.app_name)
    assertEquals("V2Tunnel VPN", appName)
  }

  @Test
  fun `parse trojan uri correctly`() {
    val uri = "trojan://secret123@sg01.v2tunnel.net:443?type=ws&security=tls&sni=speed.cloudflare.com#SG-Fast"
    val profile = VpnConfigParser.parse(uri).firstOrNull()
    assertNotNull(profile)
    assertEquals(VpnProtocol.TROJAN, profile?.protocol)
    assertEquals("sg01.v2tunnel.net", profile?.server)
    assertEquals(443, profile?.port)
    assertEquals("secret123", profile?.password)
    assertEquals("speed.cloudflare.com", profile?.sni)
  }

  @Test
  fun `room database entity and dao store and retrieve vpn configuration`() = runBlocking {
    val entity = VpnProfileEntity(
      id = 100L,
      name = "Singapore Trojan High-Speed",
      protocol = "TROJAN",
      server = "sg01.v2tunnel.net",
      port = 443,
      username = "user_fast",
      password = "trojan_secret_password",
      network = "ws",
      security = "tls",
      sni = "sg01.speedtest.net",
      path = "/trojan-ws",
      host = "sg01.speedtest.net",
      sshPayload = "GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]"
    )

    val dao = db.vpnProfileDao()
    dao.insertProfile(entity)

    val loaded = dao.getProfileById(100L)
    assertNotNull(loaded)
    assertEquals("Singapore Trojan High-Speed", loaded?.name)
    assertEquals("TROJAN", loaded?.protocol)
    assertEquals("sg01.v2tunnel.net", loaded?.server)
    assertEquals(443, loaded?.port)
    assertEquals("user_fast", loaded?.username)
    assertEquals("trojan_secret_password", loaded?.password)
    assertEquals("sg01.speedtest.net", loaded?.sni)
    assertEquals("GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]", loaded?.sshPayload)

    val trojanProfiles = dao.getProfilesByProtocol("TROJAN").first()
    assertEquals(1, trojanProfiles.size)
    assertEquals("sg01.v2tunnel.net", trojanProfiles[0].server)
  }
}

