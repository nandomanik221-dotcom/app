package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.VpnProfile
import com.example.model.VpnProtocol
import com.example.ui.components.ServerCard
import com.example.ui.theme.CyberBorder
import com.example.ui.theme.CyberCard
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.NeonPurple
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary

@Composable
fun ServersScreen(
    profiles: List<VpnProfile>,
    activeProfile: VpnProfile?,
    isPingingAll: Boolean,
    onSelectProfile: (VpnProfile) -> Unit,
    onPingProfile: (VpnProfile) -> Unit,
    onPingAll: () -> Unit,
    onFavoriteToggle: (VpnProfile) -> Unit,
    onAddProfile: () -> Unit,
    onImportProfile: () -> Unit,
    onEditProfile: (VpnProfile) -> Unit,
    onDeleteProfile: (VpnProfile) -> Unit,
    onExportProfile: (VpnProfile) -> Unit,
    modifier: Modifier = Modifier
) {
    var searchQuery by remember { mutableStateOf("") }
    var selectedProtocolFilter by remember { mutableStateOf<VpnProtocol?>(null) }

    val filteredProfiles = remember(profiles, searchQuery, selectedProtocolFilter) {
        profiles.filter { profile ->
            val matchesFilter = selectedProtocolFilter == null || profile.protocol == selectedProtocolFilter
            val matchesSearch = searchQuery.isBlank() ||
                    profile.name.contains(searchQuery, ignoreCase = true) ||
                    profile.server.contains(searchQuery, ignoreCase = true) ||
                    profile.countryCode.contains(searchQuery, ignoreCase = true)
            matchesFilter && matchesSearch
        }
    }

    Box(modifier = modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp)
        ) {
            // Header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 16.dp, bottom = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "VPN Servers",
                        style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold),
                        color = TextPrimary
                    )
                    Text(
                        text = "${profiles.size} configured server accounts",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextMuted
                    )
                }

                // Ping All Button
                Row(
                    modifier = Modifier
                        .clip(RoundedCornerShape(10.dp))
                        .background(NeonCyan.copy(alpha = 0.15f))
                        .border(1.dp, NeonCyan.copy(alpha = 0.4f), RoundedCornerShape(10.dp))
                        .clickable(enabled = !isPingingAll, onClick = onPingAll)
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = if (isPingingAll) Icons.Default.Sync else Icons.Default.Bolt,
                        contentDescription = "Ping All",
                        tint = NeonCyan,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (isPingingAll) "Testing..." else "Ping All",
                        style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                        color = NeonCyan
                    )
                }
            }

            // Search Bar
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Search by name, host, country...", color = TextMuted, fontSize = 13.sp) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = TextMuted, modifier = Modifier.size(18.dp)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp),
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = NeonCyan,
                    unfocusedBorderColor = CyberBorder,
                    focusedTextColor = TextPrimary,
                    unfocusedTextColor = TextPrimary,
                    focusedContainerColor = CyberCard,
                    unfocusedContainerColor = CyberCard
                ),
                singleLine = true
            )

            Spacer(modifier = Modifier.height(10.dp))

            // Protocol Filter Chips
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                // ALL filter
                FilterChip(
                    title = "All Protocols (${profiles.size})",
                    isSelected = selectedProtocolFilter == null,
                    color = NeonCyan,
                    onClick = { selectedProtocolFilter = null }
                )

                VpnProtocol.entries.forEach { proto ->
                    val count = profiles.count { it.protocol == proto }
                    FilterChip(
                        title = "${proto.displayName} ($count)",
                        isSelected = selectedProtocolFilter == proto,
                        color = proto.badgeColor,
                        onClick = { selectedProtocolFilter = proto }
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Server List
            if (filteredProfiles.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = "No VPN servers found",
                            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                            color = TextPrimary
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Tap the + button below to import or add accounts.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextMuted
                        )
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(
                        items = filteredProfiles,
                        key = { it.id }
                    ) { profile ->
                        ServerCard(
                            profile = profile,
                            isSelected = activeProfile?.id == profile.id,
                            onSelect = { onSelectProfile(profile) },
                            onPing = { onPingProfile(profile) },
                            onFavoriteToggle = { onFavoriteToggle(profile) },
                            onEdit = { onEditProfile(profile) },
                            onDelete = { onDeleteProfile(profile) },
                            onExport = { onExportProfile(profile) }
                        )
                    }

                    item {
                        Spacer(modifier = Modifier.height(80.dp))
                    }
                }
            }
        }

        // Floating Action Buttons (Import & Add)
        Row(
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(bottom = 20.dp, end = 20.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            FloatingActionButton(
                onClick = onImportProfile,
                containerColor = CyberCard,
                contentColor = NeonCyan,
                shape = CircleShape,
                modifier = Modifier
                    .size(48.dp)
                    .border(1.dp, CyberBorder, CircleShape)
            ) {
                Icon(Icons.Default.ContentPaste, contentDescription = "Import Link", modifier = Modifier.size(20.dp))
            }

            FloatingActionButton(
                onClick = onAddProfile,
                containerColor = NeonCyan,
                contentColor = Color.Black,
                shape = CircleShape,
                modifier = Modifier.size(56.dp)
            ) {
                Icon(Icons.Default.Add, contentDescription = "Add Server", modifier = Modifier.size(26.dp))
            }
        }
    }
}

@Composable
private fun FilterChip(
    title: String,
    isSelected: Boolean,
    color: Color,
    onClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(if (isSelected) color.copy(alpha = 0.2f) else CyberCard)
            .border(1.dp, if (isSelected) color else CyberBorder, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 6.dp)
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.SemiBold),
            color = if (isSelected) color else TextSecondary
        )
    }
}
