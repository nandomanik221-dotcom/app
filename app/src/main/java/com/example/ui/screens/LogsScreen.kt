package com.example.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.model.VpnLogEntry
import com.example.ui.components.LogConsoleView
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.TextPrimary

@Composable
fun LogsScreen(
    logs: List<VpnLogEntry>,
    onClearLogs: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp)
    ) {
        Column(modifier = Modifier.padding(top = 16.dp, bottom = 12.dp)) {
            Text(
                text = "Live Tunnel Console",
                style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold),
                color = TextPrimary
            )
            Text(
                text = "Real-time handshakes, routing tables, and socket logs",
                style = MaterialTheme.typography.bodySmall,
                color = NeonCyan
            )
        }

        LogConsoleView(
            logs = logs,
            onClear = onClearLogs,
            modifier = Modifier.weight(1f)
        )

        Spacer(modifier = Modifier.height(16.dp))
    }
}
