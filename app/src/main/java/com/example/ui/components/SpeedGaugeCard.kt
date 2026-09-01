package com.example.ui.components

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.DataUsage
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.VpnMetrics
import com.example.ui.theme.CyberBorder
import com.example.ui.theme.CyberCard
import com.example.ui.theme.CyberSurfaceVariant
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.NeonPurple
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import java.text.DecimalFormat

@Composable
fun SpeedGaugeCard(
    metrics: VpnMetrics,
    isConnected: Boolean,
    modifier: Modifier = Modifier
) {
    val infiniteTransition = rememberInfiniteTransition(label = "wave")
    val waveOffset by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(2500, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "waveOffset"
    )

    Card(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(20.dp))
            .border(1.dp, CyberBorder, RoundedCornerShape(20.dp)),
        colors = CardDefaults.cardColors(containerColor = CyberCard)
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            // Speed Row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Download Speed
                SpeedIndicator(
                    label = "DOWNLOAD",
                    speedBytes = if (isConnected) metrics.downloadSpeedBytesPerSec else 0L,
                    icon = Icons.Default.ArrowDownward,
                    color = NeonCyan,
                    modifier = Modifier.weight(1f)
                )

                // Divider line
                Box(
                    modifier = Modifier
                        .height(44.dp)
                        .width(1.dp)
                        .background(CyberBorder)
                )

                // Upload Speed
                SpeedIndicator(
                    label = "UPLOAD",
                    speedBytes = if (isConnected) metrics.uploadSpeedBytesPerSec else 0L,
                    icon = Icons.Default.ArrowUpward,
                    color = NeonPurple,
                    modifier = Modifier.weight(1f)
                )
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Animated Live Waveform Chart
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(CyberSurfaceVariant.copy(alpha = 0.6f))
            ) {
                Canvas(modifier = Modifier.matchParentSize()) {
                    val width = size.width
                    val height = size.height
                    val path = Path()

                    if (isConnected) {
                        path.moveTo(0f, height * 0.7f)
                        val points = 8
                        for (i in 0..points) {
                            val x = (width / points) * i
                            val waveHeight = if (i % 2 == 0) height * 0.25f else height * 0.75f
                            val y = waveHeight + (Math.sin(Math.toRadians(waveOffset.toDouble() + (i * 45))).toFloat() * 10f)
                            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
                        }

                        drawPath(
                            path = path,
                            brush = Brush.horizontalGradient(
                                colors = listOf(NeonCyan, NeonPurple, NeonGreen)
                            ),
                            style = Stroke(width = 3.dp.toPx())
                        )
                    } else {
                        // Flat inactive line
                        drawLine(
                            color = CyberBorder,
                            start = Offset(0f, height / 2f),
                            end = Offset(width, height / 2f),
                            strokeWidth = 2.dp.toPx()
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Total Usage Bottom Row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.DataUsage,
                        contentDescription = "Total Transferred",
                        tint = TextMuted,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "Total Traffic",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextMuted
                    )
                }

                Text(
                    text = "↓ ${formatBytes(metrics.totalDownloadBytes)}  •  ↑ ${formatBytes(metrics.totalUploadBytes)}",
                    style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.SemiBold),
                    color = TextSecondary
                )
            }
        }
    }
}

@Composable
private fun SpeedIndicator(
    label: String,
    speedBytes: Long,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    color: Color,
    modifier: Modifier = Modifier
) {
    val (speedVal, unit) = formatSpeedSplit(speedBytes)

    Row(
        modifier = modifier.padding(horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(36.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(color.copy(alpha = 0.15f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = icon,
                contentDescription = label,
                tint = color,
                modifier = Modifier.size(20.dp)
            )
        }

        Spacer(modifier = Modifier.width(10.dp))

        Column {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp, letterSpacing = 0.8.sp),
                color = TextMuted
            )
            Row(verticalAlignment = Alignment.Bottom) {
                Text(
                    text = speedVal,
                    style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold),
                    color = TextPrimary
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text(
                    text = unit,
                    style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.SemiBold),
                    color = color,
                    modifier = Modifier.padding(bottom = 2.dp)
                )
            }
        }
    }
}

private fun formatSpeedSplit(bytesPerSec: Long): Pair<String, String> {
    return when {
        bytesPerSec >= 1_000_000 -> {
            val mb = bytesPerSec / 1_000_000f
            Pair(String.format("%.1f", mb), "MB/s")
        }
        bytesPerSec >= 1_000 -> {
            val kb = bytesPerSec / 1_000L
            Pair("$kb", "KB/s")
        }
        else -> Pair("$bytesPerSec", "B/s")
    }
}

private fun formatBytes(bytes: Long): String {
    return when {
        bytes >= 1_000_000_000 -> String.format("%.2f GB", bytes / 1_000_000_000f)
        bytes >= 1_000_000 -> String.format("%.1f MB", bytes / 1_000_000f)
        bytes >= 1_000 -> "${bytes / 1000} KB"
        else -> "$bytes B"
    }
}
