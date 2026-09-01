package com.example.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.ripple
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.VpnConnectionState
import com.example.ui.theme.NeonAmber
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.NeonPurple
import com.example.ui.theme.NeonRed
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary

@Composable
fun ConnectionButton(
    connectionState: VpnConnectionState,
    durationSeconds: Long,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val isConnected = connectionState == VpnConnectionState.CONNECTED
    val isConnecting = connectionState == VpnConnectionState.CONNECTING || connectionState == VpnConnectionState.DISCONNECTING

    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = if (isConnected || isConnecting) 1.22f else 1.05f,
        animationSpec = infiniteRepeatable(
            animation = tween(1400, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "scale"
    )

    val rotationAngle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(3000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "rotation"
    )

    val glowColor by animateColorAsState(
        targetValue = when (connectionState) {
            VpnConnectionState.CONNECTED -> NeonGreen
            VpnConnectionState.CONNECTING, VpnConnectionState.DISCONNECTING -> NeonAmber
            VpnConnectionState.ERROR -> NeonRed
            VpnConnectionState.DISCONNECTED -> NeonCyan
            else -> NeonCyan
        },
        label = "glowColor"
    )

    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = modifier.padding(vertical = 12.dp)
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier.size(190.dp)
        ) {
            // Background pulsing ripples when connected or connecting
            Canvas(
                modifier = Modifier
                    .size(190.dp)
            ) {
                if (isConnected || isConnecting) {
                    drawCircle(
                        color = glowColor.copy(alpha = 0.12f),
                        radius = (size.minDimension / 2f) * (if (isConnected) pulseScale else 1f)
                    )
                    drawCircle(
                        color = glowColor.copy(alpha = 0.22f),
                        radius = (size.minDimension / 2.3f)
                    )
                }

                // Cyber dashed track ring
                drawCircle(
                    color = glowColor.copy(alpha = 0.35f),
                    radius = (size.minDimension / 2.1f),
                    style = Stroke(width = 2.dp.toPx())
                )
            }

            // Animated rotating neon arc when active
            if (isConnected || isConnecting) {
                Canvas(
                    modifier = Modifier
                        .size(180.dp)
                        .rotate(if (isConnecting) rotationAngle else 0f)
                ) {
                    drawArc(
                        brush = Brush.sweepGradient(
                            listOf(
                                Color.Transparent,
                                glowColor.copy(alpha = 0.2f),
                                glowColor,
                                Color.Transparent
                            )
                        ),
                        startAngle = 0f,
                        sweepAngle = if (isConnected) 360f else 270f,
                        useCenter = false,
                        style = Stroke(width = 4.dp.toPx())
                    )
                }
            }

            // Main center interactive button
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(136.dp)
                    .clip(CircleShape)
                    .background(
                        Brush.radialGradient(
                            colors = listOf(
                                Color(0xFF1E2D4A),
                                Color(0xFF0F1728)
                            )
                        )
                    )
                    .border(
                        width = 3.dp,
                        brush = Brush.linearGradient(
                            colors = listOf(
                                glowColor,
                                glowColor.copy(alpha = 0.4f)
                            )
                        ),
                        shape = CircleShape
                    )
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = ripple(bounded = true, color = glowColor),
                        onClick = onClick
                    )
                    .testTag("vpn_toggle_button")
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        imageVector = when (connectionState) {
                            VpnConnectionState.CONNECTED -> Icons.Default.Shield
                            VpnConnectionState.CONNECTING, VpnConnectionState.DISCONNECTING -> Icons.Default.Sync
                            else -> Icons.Default.PowerSettingsNew
                        },
                        contentDescription = "VPN Toggle",
                        tint = glowColor,
                        modifier = Modifier
                            .size(44.dp)
                            .then(if (isConnecting) Modifier.rotate(rotationAngle) else Modifier)
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = when (connectionState) {
                            VpnConnectionState.CONNECTED -> "CONNECTED"
                            VpnConnectionState.CONNECTING -> "CONNECTING"
                            VpnConnectionState.DISCONNECTING -> "STOPPING"
                            VpnConnectionState.ERROR -> "RETRY"
                            else -> "TAP TO CONNECT"
                        },
                        style = MaterialTheme.typography.labelMedium.copy(
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 1.1.sp
                        ),
                        color = glowColor,
                        fontSize = 10.sp
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Connection duration timer or status tip
        if (isConnected) {
            val hours = durationSeconds / 3600
            val minutes = (durationSeconds % 3600) / 60
            val seconds = durationSeconds % 60
            val timeFormatted = String.format("%02d:%02d:%02d", hours, minutes, seconds)

            Text(
                text = "Session Time: $timeFormatted",
                style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Medium),
                color = TextPrimary
            )
        } else {
            Text(
                text = if (isConnecting) "Establishing secure tunnel..." else "Tunnel is Disconnected",
                style = MaterialTheme.typography.bodySmall,
                color = TextMuted
            )
        }
    }
}
