package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.VpnConnectionState
import com.example.model.VpnMetrics
import com.example.model.VpnProfile
import com.example.ui.components.ActiveProfileBanner
import com.example.ui.components.ConnectionButton
import com.example.ui.components.SpeedGaugeCard
import com.example.ui.theme.CyberBorder
import com.example.ui.theme.CyberCard
import com.example.ui.theme.NeonAmber
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.NeonPurple
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary

@Composable
fun DashboardScreen(
    connectionState: VpnConnectionState,
    activeProfile: VpnProfile?,
    metrics: VpnMetrics,
    onToggleConnection: () -> Unit,
    onSwitchServer: () -> Unit,
    onPingActive: () -> Unit,
    onOpenSettings: () -> Unit,
    onNavigateToServers: () -> Unit,
    onNavigateToTools: () -> Unit,
    onNavigateToLogs: () -> Unit,
    modifier: Modifier = Modifier
) {
    val isConnected = connectionState == VpnConnectionState.CONNECTED

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp)
            .verticalScroll(rememberScrollState())
    ) {
        // App Top Bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 16.dp, bottom = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(38.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(NeonCyan.copy(alpha = 0.15f))
                        .border(1.dp, NeonCyan.copy(alpha = 0.4f), RoundedCornerShape(10.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = "App Logo",
                        tint = NeonCyan,
                        modifier = Modifier.size(22.dp)
                    )
                }
                Spacer(modifier = Modifier.width(10.dp))
                Column {
                    Text(
                        text = "V2Tunnel VPN",
                        style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold),
                        color = TextPrimary
                    )
                    Text(
                        text = "Trojan • Xray • SSH • Shadowsocks",
                        style = MaterialTheme.typography.labelSmall,
                        color = NeonCyan
                    )
                }
            }

            IconButton(
                onClick = onOpenSettings,
                modifier = Modifier
                    .size(40.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(CyberCard)
                    .border(1.dp, CyberBorder, RoundedCornerShape(10.dp))
            ) {
                Icon(
                    imageVector = Icons.Default.Settings,
                    contentDescription = "Settings",
                    tint = TextSecondary,
                    modifier = Modifier.size(20.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(6.dp))

        // Big Main Power Connect Button
        ConnectionButton(
            connectionState = connectionState,
            durationSeconds = metrics.durationSeconds,
            onClick = onToggleConnection
        )

        Spacer(modifier = Modifier.height(10.dp))

        // Selected Server Profile Card
        ActiveProfileBanner(
            profile = activeProfile,
            onSwitchClick = onSwitchServer,
            onPingClick = onPingActive
        )

        Spacer(modifier = Modifier.height(14.dp))

        // Live Speedometer & Transferred Data Card
        SpeedGaugeCard(
            metrics = metrics,
            isConnected = isConnected
        )

        Spacer(modifier = Modifier.height(14.dp))

        // IP & Protection Details Card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(16.dp))
                .border(1.dp, CyberBorder, RoundedCornerShape(16.dp)),
            colors = CardDefaults.cardColors(containerColor = CyberCard)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(
                    text = "VIRTUAL NETWORK STATUS",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp
                    ),
                    color = TextMuted
                )
                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    StatusItem(
                        icon = Icons.Default.Public,
                        label = "Public IP",
                        value = if (isConnected) metrics.publicIp else "182.1.204.55 (Real)",
                        highlight = isConnected,
                        modifier = Modifier.weight(1f)
                    )

                    StatusItem(
                        icon = Icons.Default.LocationOn,
                        label = "Location",
                        value = if (isConnected) "${activeProfile?.countryCode ?: "SG"} (Singapore)" else "Indonesia (ID)",
                        highlight = isConnected,
                        modifier = Modifier.weight(1f)
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    StatusItem(
                        icon = Icons.Default.Fingerprint,
                        label = "Protocol Mode",
                        value = activeProfile?.displaySecurityInfo ?: "Trojan / VLESS / SSH",
                        highlight = false,
                        modifier = Modifier.weight(1f)
                    )

                    StatusItem(
                        icon = Icons.Default.Dns,
                        label = "Encrypted DNS",
                        value = "1.1.1.1 (Cloudflare)",
                        highlight = false,
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Quick Tools Row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            QuickToolCard(
                icon = Icons.Default.Bolt,
                title = "All Servers",
                subtitle = "Switch / Ping",
                color = NeonCyan,
                onClick = onNavigateToServers,
                modifier = Modifier.weight(1f)
            )

            QuickToolCard(
                icon = Icons.Default.AutoAwesome,
                title = "Payloads",
                subtitle = "Bug & SNI",
                color = NeonPurple,
                onClick = onNavigateToTools,
                modifier = Modifier.weight(1f)
            )

            QuickToolCard(
                icon = Icons.Default.Terminal,
                title = "Live Logs",
                subtitle = "Console",
                color = NeonGreen,
                onClick = onNavigateToLogs,
                modifier = Modifier.weight(1f)
            )
        }

        Spacer(modifier = Modifier.height(30.dp))
    }
}

@Composable
private fun StatusItem(
    icon: ImageVector,
    label: String,
    value: String,
    highlight: Boolean,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier.padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = if (highlight) NeonCyan else TextMuted,
            modifier = Modifier.size(18.dp)
        )
        Spacer(modifier = Modifier.width(8.dp))
        Column {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp),
                color = TextMuted
            )
            Text(
                text = value,
                style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.SemiBold),
                color = if (highlight) NeonGreen else TextPrimary,
                maxLines = 1
            )
        }
    }
}

@Composable
private fun QuickToolCard(
    icon: ImageVector,
    title: String,
    subtitle: String,
    color: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .clip(RoundedCornerShape(14.dp))
            .border(1.dp, CyberBorder, RoundedCornerShape(14.dp))
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = CyberCard)
    ) {
        Column(
            modifier = Modifier.padding(12.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(32.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(color.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = color,
                    modifier = Modifier.size(18.dp)
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = title,
                style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
                color = TextPrimary
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.labelSmall,
                color = TextMuted
            )
        }
    }
}
