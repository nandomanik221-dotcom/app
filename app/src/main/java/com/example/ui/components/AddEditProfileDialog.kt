package com.example.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.model.VpnProfile
import com.example.model.VpnProtocol
import com.example.ui.theme.CyberBg
import com.example.ui.theme.CyberBorder
import com.example.ui.theme.CyberCard
import com.example.ui.theme.CyberSurfaceVariant
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddEditProfileDialog(
    initialProfile: VpnProfile?,
    onDismiss: () -> Unit,
    onSave: (VpnProfile) -> Unit
) {
    var protocol by remember { mutableStateOf(initialProfile?.protocol ?: VpnProtocol.TROJAN) }
    var name by remember { mutableStateOf(initialProfile?.name ?: "") }
    var server by remember { mutableStateOf(initialProfile?.server ?: "") }
    var port by remember { mutableStateOf((initialProfile?.port ?: 443).toString()) }
    var password by remember { mutableStateOf(initialProfile?.password ?: "") }
    var method by remember { mutableStateOf(initialProfile?.method ?: "chacha20-poly1305") }
    var network by remember { mutableStateOf(initialProfile?.network ?: "ws") }
    var security by remember { mutableStateOf(initialProfile?.security ?: "tls") }
    var sni by remember { mutableStateOf(initialProfile?.sni ?: "") }
    var path by remember { mutableStateOf(initialProfile?.path ?: "/ws") }
    var hostHeader by remember { mutableStateOf(initialProfile?.host ?: "") }
    var countryCode by remember { mutableStateOf(initialProfile?.countryCode ?: "SG") }

    // SSH Specific
    var sshUsername by remember { mutableStateOf(initialProfile?.sshUsername?.ifBlank { initialProfile.username } ?: "") }
    var sshPassword by remember { mutableStateOf(initialProfile?.sshPassword?.ifBlank { initialProfile.password } ?: "") }
    var sshPayload by remember { mutableStateOf(initialProfile?.sshPayload ?: "") }
    var sshDirectSsl by remember { mutableStateOf(initialProfile?.sshDirectSsl ?: true) }

    // Remote Proxy
    var proxyEnabled by remember { mutableStateOf(initialProfile?.remoteProxyEnabled ?: initialProfile?.proxyEnabled ?: false) }
    var proxyHost by remember { mutableStateOf(initialProfile?.remoteProxyHost ?: initialProfile?.proxyHost ?: "") }
    var proxyPort by remember { mutableStateOf((initialProfile?.remoteProxyPort ?: initialProfile?.proxyPort ?: 8080).toString()) }
    var proxyUsername by remember { mutableStateOf(initialProfile?.remoteProxyUsername ?: initialProfile?.proxyUsername ?: "") }
    var proxyPassword by remember { mutableStateOf(initialProfile?.remoteProxyPassword ?: initialProfile?.proxyPassword ?: "") }
    var proxyType by remember { mutableStateOf(initialProfile?.remoteProxyType ?: initialProfile?.proxyType ?: "HTTP") }

    // HTTP Custom style "Proxy Jarak Jauh" raw input
    var rawProxyAddressInput by remember {
        val initialFormatted = if (proxyHost.isNotBlank()) {
            com.example.parser.RemoteProxyAddressParser.format(
                host = proxyHost,
                port = proxyPort.toIntOrNull() ?: 8080,
                username = proxyUsername.ifBlank { null },
                password = proxyPassword.ifBlank { null }
            )
        } else ""
        mutableStateOf(initialFormatted)
    }

    var protocolExpanded by remember { mutableStateOf(false) }
    var networkExpanded by remember { mutableStateOf(false) }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth(0.94f)
                .clip(RoundedCornerShape(24.dp))
                .border(1.dp, CyberBorder, RoundedCornerShape(24.dp)),
            color = CyberBg
        ) {
            Column(
                modifier = Modifier
                    .padding(20.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                // Header
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = if (initialProfile == null) "Add VPN Configuration" else "Edit VPN Profile",
                            style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold),
                            color = TextPrimary
                        )
                        Text(
                            text = "Trojan • VLESS • VMess • Shadowsocks • SSH",
                            style = MaterialTheme.typography.bodySmall,
                            color = NeonCyan
                        )
                    }

                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = "Close", tint = TextMuted)
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Protocol selector pills
                Text(
                    text = "Select Protocol",
                    style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.SemiBold),
                    color = TextSecondary
                )
                Spacer(modifier = Modifier.height(6.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    listOf(
                        VpnProtocol.TROJAN,
                        VpnProtocol.VLESS,
                        VpnProtocol.VMESS,
                        VpnProtocol.SHADOWSOCKS,
                        VpnProtocol.SSH
                    ).forEach { proto ->
                        val isSel = protocol == proto
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(8.dp))
                                .background(if (isSel) proto.badgeColor.copy(alpha = 0.25f) else CyberCard)
                                .border(
                                    1.dp,
                                    if (isSel) proto.badgeColor else CyberBorder,
                                    RoundedCornerShape(8.dp)
                                )
                                .clickable {
                                    protocol = proto
                                    if (name.isBlank() || name.startsWith("My ")) {
                                        name = "${proto.displayName} Config"
                                    }
                                }
                                .padding(vertical = 8.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = when (proto) {
                                    VpnProtocol.SHADOWSOCKS -> "SS"
                                    VpnProtocol.VLESS -> "VLESS"
                                    VpnProtocol.VMESS -> "VMess"
                                    else -> proto.displayName
                                },
                                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                                color = if (isSel) proto.badgeColor else TextSecondary,
                                maxLines = 1
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Profile Name
                CyberTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = "Profile Name / Remark",
                    placeholder = "e.g. 🇸🇬 SG-01 Fast Trojan"
                )

                Spacer(modifier = Modifier.height(10.dp))

                // Server Address & Port Row
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    CyberTextField(
                        value = server,
                        onValueChange = { server = it },
                        label = "Server / Domain / IP",
                        placeholder = "sg01.v2tunnel.net",
                        modifier = Modifier.weight(2.5f)
                    )

                    CyberTextField(
                        value = port,
                        onValueChange = { port = it },
                        label = "Port",
                        placeholder = "443",
                        modifier = Modifier.weight(1.2f)
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))

                // Country Code
                CyberTextField(
                    value = countryCode,
                    onValueChange = { countryCode = it.take(2).uppercase() },
                    label = "Country Code (Flag)",
                    placeholder = "SG, ID, US, JP, DE, HK"
                )

                Spacer(modifier = Modifier.height(10.dp))

                // Protocol Specific Fields
                when (protocol) {
                    VpnProtocol.TROJAN, VpnProtocol.VLESS, VpnProtocol.VMESS -> {
                        CyberTextField(
                            value = password,
                            onValueChange = { password = it },
                            label = if (protocol == VpnProtocol.TROJAN) "Trojan Password" else "UUID / User ID",
                            placeholder = "Enter password or UUID"
                        )

                        Spacer(modifier = Modifier.height(10.dp))

                        // SNI / Bug Host
                        CyberTextField(
                            value = sni,
                            onValueChange = { sni = it },
                            label = "SNI / Server Name Indication (Bug Host)",
                            placeholder = "e.g. speed.cloudflare.com"
                        )

                        Spacer(modifier = Modifier.height(10.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            CyberTextField(
                                value = network,
                                onValueChange = { network = it },
                                label = "Network",
                                placeholder = "ws / grpc / tcp",
                                modifier = Modifier.weight(1f)
                            )
                            CyberTextField(
                                value = path,
                                onValueChange = { path = it },
                                label = "Path",
                                placeholder = "/v2ray-ws",
                                modifier = Modifier.weight(1f)
                            )
                        }
                    }

                    VpnProtocol.SHADOWSOCKS -> {
                        CyberTextField(
                            value = password,
                            onValueChange = { password = it },
                            label = "Shadowsocks Password / Secret",
                            placeholder = "Enter encryption key"
                        )

                        Spacer(modifier = Modifier.height(10.dp))

                        CyberTextField(
                            value = method,
                            onValueChange = { method = it },
                            label = "Encryption Method (AEAD)",
                            placeholder = "chacha20-ietf-poly1305 / aes-256-gcm"
                        )
                    }

                    VpnProtocol.SSH -> {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            CyberTextField(
                                value = sshUsername,
                                onValueChange = { sshUsername = it },
                                label = "SSH Username",
                                placeholder = "root / vpnuser",
                                modifier = Modifier.weight(1f)
                            )
                            CyberTextField(
                                value = sshPassword,
                                onValueChange = { sshPassword = it },
                                label = "SSH Password",
                                placeholder = "password",
                                modifier = Modifier.weight(1f)
                            )
                        }

                        Spacer(modifier = Modifier.height(10.dp))

                        CyberTextField(
                            value = sni,
                            onValueChange = { sni = it },
                            label = "SNI / Bug Host (Separate Field)",
                            placeholder = "e.g. m.youtube.com / line.me"
                        )

                        Spacer(modifier = Modifier.height(10.dp))

                        CyberTextField(
                            value = sshPayload,
                            onValueChange = { sshPayload = it },
                            label = "Custom HTTP / WebSocket Payload",
                            placeholder = "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]",
                            singleLine = false,
                            minLines = 2
                        )

                        Spacer(modifier = Modifier.height(12.dp))

                        // Direct SSL/TLS Mode Switch
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column {
                                Text(
                                    text = "Direct SSL/TLS Mode",
                                    style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                                    color = TextPrimary
                                )
                                Text(
                                    text = "Wraps SSH connection inside TLS using SNI",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = TextMuted
                                )
                            }
                            Switch(
                                checked = sshDirectSsl,
                                onCheckedChange = { sshDirectSsl = it },
                                colors = SwitchDefaults.colors(
                                    checkedThumbColor = NeonCyan,
                                    checkedTrackColor = NeonCyan.copy(alpha = 0.4f)
                                )
                            )
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        // Remote Proxy Configuration Section (HTTP Custom style "Proxy Jarak Jauh")
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column {
                                Text(
                                    text = "Proxy Jarak Jauh (Remote Proxy)",
                                    style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                                    color = TextPrimary
                                )
                                Text(
                                    text = "Route SSH handshake via HTTP CONNECT / SOCKS5 proxy",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = TextMuted
                                )
                            }
                            Switch(
                                checked = proxyEnabled,
                                onCheckedChange = { proxyEnabled = it },
                                colors = SwitchDefaults.colors(
                                    checkedThumbColor = NeonGreen,
                                    checkedTrackColor = NeonGreen.copy(alpha = 0.4f)
                                )
                            )
                        }

                        if (proxyEnabled) {
                            Spacer(modifier = Modifier.height(8.dp))

                            // HTTP Custom unified format input: host:port or user:pass@host:port or user:pass@[IPv6]:port
                            CyberTextField(
                                value = rawProxyAddressInput,
                                onValueChange = { input ->
                                    rawProxyAddressInput = input
                                    val parsed = com.example.parser.RemoteProxyAddressParser.parse(input)
                                    if (parsed != null) {
                                        proxyHost = parsed.host
                                        proxyPort = parsed.port.toString()
                                        if (parsed.username != null) proxyUsername = parsed.username
                                        if (parsed.password != null) proxyPassword = parsed.password
                                    }
                                },
                                label = "Proxy Jarak Jauh [ host:port / user:pass@host:port ]",
                                placeholder = "ads.ruangguru.com:443 or user:pass@104.21.56.88:8080"
                            )

                            Spacer(modifier = Modifier.height(8.dp))

                            // Proxy Type selector: [ HTTP ] [ SOCKS5 ]
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(10.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "Proxy Type:",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = TextSecondary
                                )
                                listOf("HTTP", "SOCKS5").forEach { type ->
                                    val isTypeSel = proxyType.equals(type, ignoreCase = true)
                                    Box(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(8.dp))
                                            .background(if (isTypeSel) NeonGreen.copy(alpha = 0.2f) else CyberCard)
                                            .border(1.dp, if (isTypeSel) NeonGreen else CyberBorder, RoundedCornerShape(8.dp))
                                            .clickable { proxyType = type }
                                            .padding(horizontal = 14.dp, vertical = 6.dp)
                                    ) {
                                        Text(
                                            text = type,
                                            style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                                            color = if (isTypeSel) NeonGreen else TextMuted
                                        )
                                    }
                                }
                            }

                            Spacer(modifier = Modifier.height(8.dp))

                            // Optional separate Host & Port granular controls
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                CyberTextField(
                                    value = proxyHost,
                                    onValueChange = {
                                        proxyHost = it
                                        rawProxyAddressInput = com.example.parser.RemoteProxyAddressParser.format(
                                            proxyHost, proxyPort.toIntOrNull() ?: 8080, proxyUsername.ifBlank { null }, proxyPassword.ifBlank { null }
                                        )
                                    },
                                    label = "Host / IP",
                                    placeholder = "104.21.56.88",
                                    modifier = Modifier.weight(2.5f)
                                )
                                CyberTextField(
                                    value = proxyPort,
                                    onValueChange = {
                                        proxyPort = it
                                        rawProxyAddressInput = com.example.parser.RemoteProxyAddressParser.format(
                                            proxyHost, it.toIntOrNull() ?: 8080, proxyUsername.ifBlank { null }, proxyPassword.ifBlank { null }
                                        )
                                    },
                                    label = "Port",
                                    placeholder = "8080",
                                    modifier = Modifier.weight(1.2f)
                                )
                            }

                            Spacer(modifier = Modifier.height(8.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                CyberTextField(
                                    value = proxyUsername,
                                    onValueChange = {
                                        proxyUsername = it
                                        rawProxyAddressInput = com.example.parser.RemoteProxyAddressParser.format(
                                            proxyHost, proxyPort.toIntOrNull() ?: 8080, it.ifBlank { null }, proxyPassword.ifBlank { null }
                                        )
                                    },
                                    label = "Username (opsional)",
                                    placeholder = "user",
                                    modifier = Modifier.weight(1f)
                                )
                                CyberTextField(
                                    value = proxyPassword,
                                    onValueChange = {
                                        proxyPassword = it
                                        rawProxyAddressInput = com.example.parser.RemoteProxyAddressParser.format(
                                            proxyHost, proxyPort.toIntOrNull() ?: 8080, proxyUsername.ifBlank { null }, it.ifBlank { null }
                                        )
                                    },
                                    label = "Password (opsional)",
                                    placeholder = "pass",
                                    modifier = Modifier.weight(1f)
                                )
                            }
                        }
                    }
                    else -> {}
                }

                Spacer(modifier = Modifier.height(20.dp))

                // Action Buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    TextButton(onClick = onDismiss) {
                        Text("Cancel", color = TextMuted)
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                        onClick = {
                            val parsedPort = port.toIntOrNull() ?: 443
                            val parsedProxyPort = proxyPort.toIntOrNull() ?: 8080
                            val finalName = if (name.isNotBlank()) name else "${protocol.displayName} Server"
                            val effectiveUser = if (protocol == VpnProtocol.SSH) sshUsername.trim() else password.trim()
                            val effectivePass = if (protocol == VpnProtocol.SSH) sshPassword.trim() else password.trim()

                            val newProfile = VpnProfile(
                                id = initialProfile?.id ?: 0L,
                                name = finalName,
                                protocol = protocol,
                                server = server.trim(),
                                port = parsedPort,
                                username = effectiveUser,
                                password = effectivePass,
                                method = method.trim(),
                                network = network.trim(),
                                security = if (protocol == VpnProtocol.SSH) (if (sshDirectSsl) "tls" else "none") else security.trim(),
                                sni = sni.trim(),
                                path = path.trim(),
                                host = hostHeader.trim(),
                                sshUsername = sshUsername.trim(),
                                sshPassword = sshPassword.trim(),
                                sshPayload = sshPayload.trim(),
                                sshDirectSsl = sshDirectSsl,
                                remoteProxyEnabled = proxyEnabled,
                                remoteProxyType = proxyType.trim(),
                                remoteProxyHost = proxyHost.trim(),
                                remoteProxyPort = parsedProxyPort,
                                remoteProxyUsername = proxyUsername.trim().ifBlank { null },
                                remoteProxyPassword = proxyPassword.trim().ifBlank { null },
                                countryCode = if (countryCode.isNotBlank()) countryCode.trim().uppercase() else "SG",
                                isFavorite = initialProfile?.isFavorite ?: false
                            )
                            onSave(newProfile)
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                        shape = RoundedCornerShape(12.dp),
                        enabled = server.isNotBlank()
                    ) {
                        Icon(Icons.Default.Save, contentDescription = null, tint = Color.Black, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Save Configuration", color = Color.Black, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}

@Composable
fun CyberTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    placeholder: String = "",
    modifier: Modifier = Modifier,
    singleLine: Boolean = true,
    minLines: Int = 1
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label, color = TextSecondary, fontSize = 12.sp) },
        placeholder = { Text(placeholder, color = TextMuted, fontSize = 12.sp) },
        singleLine = singleLine,
        minLines = minLines,
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = NeonCyan,
            unfocusedBorderColor = CyberBorder,
            focusedTextColor = TextPrimary,
            unfocusedTextColor = TextPrimary,
            focusedContainerColor = CyberCard,
            unfocusedContainerColor = CyberCard
        )
    )
}
