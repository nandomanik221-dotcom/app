package com.example.ui.components

import android.content.ClipboardManager
import android.content.Context
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
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Download
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.ui.theme.CyberBg
import com.example.ui.theme.CyberBorder
import com.example.ui.theme.CyberCard
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonPurple
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary

@Composable
fun PayloadGeneratorDialog(
    onDismiss: () -> Unit,
    onApplyPayload: (payload: String, bugHost: String) -> Unit
) {
    val context = LocalContext.current
    var urlHost by remember { mutableStateOf("m.youtube.com") }
    var requestMethod by remember { mutableStateOf("GET") }
    var injectionType by remember { mutableStateOf("Front Inject") }
    var isKeepAlive by remember { mutableStateOf(true) }
    var isUserAgent by remember { mutableStateOf(true) }
    var isForwardHost by remember { mutableStateOf(true) }
    var isDualConnect by remember { mutableStateOf(false) }

    val methods = listOf("GET", "POST", "CONNECT", "HEAD", "PUT")
    val bugPresets = listOf(
        "speed.cloudflare.com" to "Cloudflare CDN",
        "m.youtube.com" to "Telkomsel / Indosat",
        "quiz.vidio.com" to "XL / Axis Edu",
        "api.midtrans.com" to "Indosat Ooredoo",
        "zoom.us" to "Telkomsel Conference"
    )

    fun generatePayload(): String {
        val host = urlHost.ifBlank { "[host]" }
        val sb = StringBuilder()

        when (injectionType) {
            "Front Inject" -> {
                sb.append("$requestMethod http://$host/ HTTP/1.1[crlf]")
                sb.append("Host: $host[crlf]")
                if (isForwardHost) sb.append("X-Online-Host: $host[crlf]X-Forward-Host: $host[crlf]")
                if (isUserAgent) sb.append("User-Agent: [ua][crlf]")
                if (isKeepAlive) sb.append("Connection: Keep-Alive[crlf]Proxy-Connection: Keep-Alive[crlf]")
                sb.append("Upgrade: websocket[crlf][crlf]")
                if (isDualConnect) sb.append("[split]CONNECT [host_port] HTTP/1.1[crlf][crlf]")
            }
            "Back Inject" -> {
                sb.append("CONNECT [host_port] HTTP/1.1[crlf][crlf]")
                sb.append("[split]$requestMethod http://$host/ HTTP/1.1[crlf]Host: $host[crlf]")
                if (isKeepAlive) sb.append("Connection: Keep-Alive[crlf]")
                sb.append("[crlf]")
            }
            else -> {
                sb.append("$requestMethod / HTTP/1.1[crlf]")
                sb.append("Host: $host[crlf]")
                sb.append("Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]")
            }
        }
        return sb.toString()
    }

    val generatedPayload = remember(urlHost, requestMethod, injectionType, isKeepAlive, isUserAgent, isForwardHost, isDualConnect) {
        generatePayload()
    }

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
                            text = "Payload & Bug Host Generator",
                            style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold),
                            color = TextPrimary
                        )
                        Text(
                            text = "HTTP Injector / Custom SSH & WebSocket style",
                            style = MaterialTheme.typography.bodySmall,
                            color = NeonCyan
                        )
                    }

                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = "Close", tint = TextMuted)
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // Bug Host Preset Chips
                Text(
                    text = "Preset Bug Host (Indonesian ISPs):",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary
                )
                Spacer(modifier = Modifier.height(6.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    bugPresets.take(3).forEach { (bug, desc) ->
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(8.dp))
                                .background(if (urlHost == bug) NeonCyan.copy(alpha = 0.2f) else CyberCard)
                                .border(1.dp, if (urlHost == bug) NeonCyan else CyberBorder, RoundedCornerShape(8.dp))
                                .clickable { urlHost = bug }
                                .padding(horizontal = 8.dp, vertical = 6.dp)
                        ) {
                            Text(
                                text = desc,
                                style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp),
                                color = if (urlHost == bug) NeonCyan else TextSecondary
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                CyberTextField(
                    value = urlHost,
                    onValueChange = { urlHost = it },
                    label = "URL / Bug Host / SNI",
                    placeholder = "e.g. m.youtube.com"
                )

                Spacer(modifier = Modifier.height(12.dp))

                // Request Method Row
                Text(
                    text = "Request Method",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary
                )
                Spacer(modifier = Modifier.height(6.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    methods.forEach { m ->
                        val isSel = requestMethod == m
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(8.dp))
                                .background(if (isSel) NeonPurple.copy(alpha = 0.3f) else CyberCard)
                                .border(1.dp, if (isSel) NeonPurple else CyberBorder, RoundedCornerShape(8.dp))
                                .clickable { requestMethod = m }
                                .padding(vertical = 6.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = m,
                                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                                color = if (isSel) NeonPurple else TextSecondary
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Extra Options
                Column {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(
                            checked = isForwardHost,
                            onCheckedChange = { isForwardHost = it },
                            colors = CheckboxDefaults.colors(checkedColor = NeonCyan)
                        )
                        Text("Forward Host / Online Host", style = MaterialTheme.typography.bodySmall, color = TextPrimary)
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(
                            checked = isKeepAlive,
                            onCheckedChange = { isKeepAlive = it },
                            colors = CheckboxDefaults.colors(checkedColor = NeonCyan)
                        )
                        Text("Keep-Alive & WebSocket Upgrade", style = MaterialTheme.typography.bodySmall, color = TextPrimary)
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                // Generated Output
                Text(
                    text = "Generated Payload Output:",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary
                )
                Spacer(modifier = Modifier.height(4.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(CyberCard)
                        .border(1.dp, CyberBorder, RoundedCornerShape(12.dp))
                        .padding(12.dp)
                ) {
                    Text(
                        text = generatedPayload,
                        style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                        color = NeonCyan
                    )
                }

                Spacer(modifier = Modifier.height(18.dp))

                // Action Buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedButton(
                        onClick = {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            val clip = android.content.ClipData.newPlainText("VPN Payload", generatedPayload)
                            clipboard.setPrimaryClip(clip)
                        },
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary)
                    ) {
                        Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Copy")
                    }

                    Button(
                        onClick = {
                            onApplyPayload(generatedPayload, urlHost)
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = Color.Black, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Apply to Profile", color = Color.Black, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}
