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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.parser.HostPortParser
import com.example.parser.RemoteProxyAddressParser
import com.example.ui.theme.CyberBorder
import com.example.ui.theme.CyberCard
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary

/**
 * Standard SSH configuration UI component matching HTTP Custom / NikuVPN design.
 *
 * Exclusively displays:
 * 1. SECTION SNI: SNI, SNI Version, Insecure toggle
 * 2. SECTION AKUN: SSH Host:Port, Username, Password
 * 3. SECTION TRANSPORT: Standard / HCR, Use payload switch
 * 4. SECTION METODE: Enhanced / TLS / SlowDNS
 * 5. SECTION PAYLOAD: Custom payload multiline, Remote proxy host:port
 *
 * WebSocket Path and unwanted fields are strictly excluded.
 */
@Composable
fun SshConfigSection(
    sni: String,
    onSniChange: (String) -> Unit,
    sniVersion: String,
    onSniVersionChange: (String) -> Unit,
    allowInsecure: Boolean,
    onAllowInsecureChange: (Boolean) -> Unit,
    sshHostPort: String,
    onSshHostPortChange: (String) -> Unit,
    sshUsername: String,
    onSshUsernameChange: (String) -> Unit,
    sshPassword: String,
    onSshPasswordChange: (String) -> Unit,
    sshTransport: String,
    onSshTransportChange: (String) -> Unit,
    sshPayloadEnabled: Boolean,
    onSshPayloadEnabledChange: (Boolean) -> Unit,
    sshMethod: String,
    onSshMethodChange: (String) -> Unit,
    sshPayload: String,
    onSshPayloadChange: (String) -> Unit,
    remoteProxy: String,
    onRemoteProxyChange: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    var passwordVisible by remember { mutableStateOf(false) }
    var sniVersionExpanded by remember { mutableStateOf(false) }

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // ==========================================
        // 1. SECTION SNI
        // ==========================================
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .background(CyberCard)
                .border(1.dp, CyberBorder, RoundedCornerShape(14.dp))
                .padding(16.dp)
        ) {
            Text(
                text = "SECTION SNI",
                style = MaterialTheme.typography.labelSmall.copy(
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp
                ),
                color = NeonCyan
            )

            Spacer(modifier = Modifier.height(10.dp))

            CyberTextField(
                value = sni,
                onValueChange = onSniChange,
                label = "SNI (Server Name Indication)",
                placeholder = "prem.nikuvpn.biz.id:443"
            )

            Spacer(modifier = Modifier.height(10.dp))

            // Versi SNI Dropdown
            Text(
                text = "Versi SNI",
                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.SemiBold),
                color = TextSecondary
            )
            Spacer(modifier = Modifier.height(4.dp))
            Box(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(CyberBorder.copy(alpha = 0.3f))
                        .border(1.dp, CyberBorder, RoundedCornerShape(12.dp))
                        .clickable { sniVersionExpanded = true }
                        .padding(horizontal = 14.dp, vertical = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = sniVersion.ifBlank { "Default" },
                        color = TextPrimary,
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Icon(
                        imageVector = Icons.Default.ArrowDropDown,
                        contentDescription = "Pilih versi SNI",
                        tint = TextSecondary
                    )
                }

                DropdownMenu(
                    expanded = sniVersionExpanded,
                    onDismissRequest = { sniVersionExpanded = false }
                ) {
                    listOf("Default", "TLSv1.2", "TLSv1.3").forEach { ver ->
                        DropdownMenuItem(
                            text = { Text(ver) },
                            onClick = {
                                onSniVersionChange(ver)
                                sniVersionExpanded = false
                            }
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
            HorizontalDivider(color = CyberBorder, thickness = 0.5.dp)
            Spacer(modifier = Modifier.height(12.dp))

            // Izinkan koneksi tidak aman
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
                    Text(
                        text = "Izinkan koneksi tidak aman",
                        style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                        color = TextPrimary
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = "Lewati verifikasi sertifikat server. Aktifkan hanya jika Anda mempercayai server.",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextMuted,
                        lineHeight = 16.sp
                    )
                }

                Switch(
                    checked = allowInsecure,
                    onCheckedChange = onAllowInsecureChange,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = NeonCyan,
                        checkedTrackColor = NeonCyan.copy(alpha = 0.4f)
                    )
                )
            }
        }

        // ==========================================
        // 2. SECTION AKUN
        // ==========================================
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .background(CyberCard)
                .border(1.dp, CyberBorder, RoundedCornerShape(14.dp))
                .padding(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(text = "👤⚙", fontSize = 16.sp)
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = "Akun",
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = TextPrimary
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            // SSH Host:Port
            CyberTextField(
                value = sshHostPort,
                onValueChange = onSshHostPortChange,
                label = "SSH Host:Port",
                placeholder = "prem.nikuvpn.biz.id:443"
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Gunakan host:port, contoh: ssh.example.com:22 atau [2001:db8::1]:22",
                style = MaterialTheme.typography.bodySmall,
                color = TextMuted,
                fontSize = 11.sp
            )

            Spacer(modifier = Modifier.height(10.dp))

            // Nama pengguna SSH
            CyberTextField(
                value = sshUsername,
                onValueChange = onSshUsernameChange,
                label = "Nama pengguna SSH",
                placeholder = "testione"
            )

            Spacer(modifier = Modifier.height(10.dp))

            // Kata sandi SSH with toggle
            CyberTextField(
                value = sshPassword,
                onValueChange = onSshPasswordChange,
                label = "Kata sandi SSH",
                placeholder = "•••••",
                visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = {
                    IconButton(onClick = { passwordVisible = !passwordVisible }) {
                        Icon(
                            imageVector = if (passwordVisible) Icons.Default.Visibility else Icons.Default.VisibilityOff,
                            contentDescription = if (passwordVisible) "Sembunyikan password" else "Tampilkan password",
                            tint = TextMuted
                        )
                    }
                }
            )
        }

        // ==========================================
        // 3. SECTION TRANSPORT
        // ==========================================
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .background(CyberCard)
                .border(1.dp, CyberBorder, RoundedCornerShape(14.dp))
                .padding(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(text = "⚙", fontSize = 16.sp)
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = "Transport",
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = TextPrimary
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Transport chips: [ Standard ] [ HCR ]
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                listOf("Standard", "HCR").forEach { transportOption ->
                    val isSelected = sshTransport.equals(transportOption, ignoreCase = true)
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .clip(RoundedCornerShape(10.dp))
                            .background(if (isSelected) NeonCyan.copy(alpha = 0.2f) else CyberBorder.copy(alpha = 0.2f))
                            .border(
                                1.dp,
                                if (isSelected) NeonCyan else CyberBorder,
                                RoundedCornerShape(10.dp)
                            )
                            .clickable { onSshTransportChange(transportOption.uppercase()) }
                            .padding(vertical = 10.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            if (isSelected) {
                                Icon(
                                    imageVector = Icons.Default.Check,
                                    contentDescription = null,
                                    tint = NeonCyan,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                            }
                            Text(
                                text = transportOption,
                                style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                                color = if (isSelected) NeonCyan else TextSecondary
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Gunakan payload switch
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Gunakan payload",
                    style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                    color = TextPrimary
                )

                Switch(
                    checked = sshPayloadEnabled,
                    onCheckedChange = onSshPayloadEnabledChange,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = NeonCyan,
                        checkedTrackColor = NeonCyan.copy(alpha = 0.4f)
                    )
                )
            }
        }

        // ==========================================
        // 4. SECTION METHOD
        // ==========================================
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .background(CyberCard)
                .border(1.dp, CyberBorder, RoundedCornerShape(14.dp))
                .padding(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(text = "⚙", fontSize = 16.sp)
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = "Metode",
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = TextPrimary
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Method chips: [ Enhanced ] [ TLS ] [ SlowDNS ]
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                listOf("Enhanced", "TLS", "SlowDNS").forEach { methodOption ->
                    val isSelected = sshMethod.equals(methodOption, ignoreCase = true)
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .clip(RoundedCornerShape(10.dp))
                            .background(if (isSelected) NeonGreen.copy(alpha = 0.2f) else CyberBorder.copy(alpha = 0.2f))
                            .border(
                                1.dp,
                                if (isSelected) NeonGreen else CyberBorder,
                                RoundedCornerShape(10.dp)
                            )
                            .clickable { onSshMethodChange(methodOption) }
                            .padding(vertical = 10.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            if (isSelected) {
                                Icon(
                                    imageVector = Icons.Default.Check,
                                    contentDescription = null,
                                    tint = NeonGreen,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                            }
                            Text(
                                text = methodOption,
                                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                                color = if (isSelected) NeonGreen else TextSecondary
                            )
                        }
                    }
                }
            }
        }

        // ==========================================
        // 5. SECTION PAYLOAD
        // ==========================================
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .background(CyberCard)
                .border(1.dp, CyberBorder, RoundedCornerShape(14.dp))
                .padding(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(text = "◉", color = NeonCyan, fontSize = 14.sp)
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = "Payload",
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = TextPrimary
                )
            }

            if (sshPayloadEnabled) {
                Spacer(modifier = Modifier.height(10.dp))

                // Payload kustom
                CyberTextField(
                    value = sshPayload,
                    onValueChange = onSshPayloadChange,
                    label = "Payload kustom",
                    placeholder = "PATCH / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]",
                    singleLine = false,
                    minLines = 3
                )

                Spacer(modifier = Modifier.height(10.dp))

                // Proxy jarak jauh
                CyberTextField(
                    value = remoteProxy,
                    onValueChange = onRemoteProxyChange,
                    label = "Proxy jarak jauh",
                    placeholder = "ads.ruangguru.com:443"
                )
            } else {
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "Payload kustom dinonaktifkan. Menggunakan koneksi langsung tanpa injeksi payload.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextMuted
                )
            }
        }
    }
}
