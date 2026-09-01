package com.example.ui.screens

import android.widget.Toast
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.model.VpnProfile
import com.example.model.VpnProtocol
import com.example.parser.VpnConfigParser
import com.example.ui.components.AddEditProfileDialog
import com.example.ui.components.ImportConfigDialog
import com.example.ui.components.PayloadGeneratorDialog
import com.example.ui.components.SettingsSheet
import com.example.ui.theme.CyberBg
import com.example.ui.theme.CyberBorder
import com.example.ui.theme.CyberCard
import com.example.ui.theme.CyberSurface
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.NeonPurple
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.example.ui.viewmodel.VpnViewModel

enum class MainTab(val title: String, val activeIcon: ImageVector, val inactiveIcon: ImageVector) {
    DASHBOARD("Home", Icons.Filled.Home, Icons.Outlined.Home),
    SERVERS("Servers", Icons.Filled.Storage, Icons.Outlined.Storage),
    TOOLS("Tools", Icons.Filled.AutoAwesome, Icons.Filled.AutoAwesome),
    LOGS("Logs", Icons.Filled.Terminal, Icons.Outlined.Terminal)
}

@Composable
fun MainAppScreen(
    viewModel: VpnViewModel,
    onPrepareVpn: () -> Unit
) {
    val context = LocalContext.current

    val profiles by viewModel.profiles.collectAsStateWithLifecycle()
    val activeProfile by viewModel.activeProfile.collectAsStateWithLifecycle()
    val connectionState by viewModel.connectionState.collectAsStateWithLifecycle()
    val metrics by viewModel.metrics.collectAsStateWithLifecycle()
    val logs by viewModel.logs.collectAsStateWithLifecycle()
    val selectedDns by viewModel.selectedDns.collectAsStateWithLifecycle()
    val isBypassLan by viewModel.isBypassLan.collectAsStateWithLifecycle()
    val isUdpForwarding by viewModel.isUdpForwarding.collectAsStateWithLifecycle()
    val isKillSwitch by viewModel.isKillSwitch.collectAsStateWithLifecycle()
    val isPingingAll by viewModel.isPingingAll.collectAsStateWithLifecycle()

    var currentTab by remember { mutableStateOf(MainTab.DASHBOARD) }

    // Dialog & Sheet States
    var showAddEditDialog by remember { mutableStateOf(false) }
    var editingProfile by remember { mutableStateOf<VpnProfile?>(null) }
    var showImportDialog by remember { mutableStateOf(false) }
    var showPayloadDialog by remember { mutableStateOf(false) }
    var showSettingsSheet by remember { mutableStateOf(false) }

    Scaffold(
        containerColor = CyberBg,
        bottomBar = {
            NavigationBar(
                containerColor = CyberSurface,
                tonalElevation = 8.dp,
                modifier = Modifier
                    .border(0.5.dp, CyberBorder)
                    .windowInsetsPadding(WindowInsets.navigationBars)
            ) {
                MainTab.entries.forEach { tab ->
                    val isSelected = currentTab == tab
                    NavigationBarItem(
                        selected = isSelected,
                        onClick = { currentTab = tab },
                        icon = {
                            Icon(
                                imageVector = if (isSelected) tab.activeIcon else tab.inactiveIcon,
                                contentDescription = tab.title,
                                modifier = Modifier.size(22.dp)
                            )
                        },
                        label = {
                            Text(
                                text = tab.title,
                                style = MaterialTheme.typography.labelSmall.copy(fontSize = 11.sp),
                                color = if (isSelected) NeonCyan else TextMuted
                            )
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = NeonCyan,
                            unselectedIconColor = TextMuted,
                            indicatorColor = NeonCyan.copy(alpha = 0.15f)
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            AnimatedContent(
                targetState = currentTab,
                transitionSpec = { fadeIn() togetherWith fadeOut() },
                label = "tabTransition"
            ) { tab ->
                when (tab) {
                    MainTab.DASHBOARD -> {
                        DashboardScreen(
                            connectionState = connectionState,
                            activeProfile = activeProfile,
                            metrics = metrics,
                            onToggleConnection = {
                                viewModel.toggleConnection(context, onPrepareVpn)
                            },
                            onSwitchServer = { currentTab = MainTab.SERVERS },
                            onPingActive = {
                                activeProfile?.let { viewModel.pingProfile(it) }
                            },
                            onOpenSettings = { showSettingsSheet = true },
                            onNavigateToServers = { currentTab = MainTab.SERVERS },
                            onNavigateToTools = { currentTab = MainTab.TOOLS },
                            onNavigateToLogs = { currentTab = MainTab.LOGS }
                        )
                    }

                    MainTab.SERVERS -> {
                        ServersScreen(
                            profiles = profiles,
                            activeProfile = activeProfile,
                            isPingingAll = isPingingAll,
                            onSelectProfile = { profile ->
                                viewModel.selectProfile(profile)
                            },
                            onPingProfile = { profile ->
                                viewModel.pingProfile(profile)
                            },
                            onPingAll = { viewModel.pingAll() },
                            onFavoriteToggle = { profile ->
                                viewModel.toggleFavorite(profile)
                            },
                            onAddProfile = {
                                editingProfile = null
                                showAddEditDialog = true
                            },
                            onImportProfile = { showImportDialog = true },
                            onEditProfile = { profile ->
                                editingProfile = profile
                                showAddEditDialog = true
                            },
                            onDeleteProfile = { profile ->
                                viewModel.deleteProfile(profile)
                                Toast.makeText(context, "Deleted ${profile.name}", Toast.LENGTH_SHORT).show()
                            },
                            onExportProfile = { profile ->
                                try {
                                    val shareIntent = com.example.parser.NikuVpnProfileExporter.createShareFileIntent(context, profile)
                                    context.startActivity(android.content.Intent.createChooser(shareIntent, "Export / Share .nikuvpn.tl Configuration"))
                                } catch (e: Exception) {
                                    val json = com.example.parser.NikuVpnProfileExporter.exportToJson(profile)
                                    val sendIntent = android.content.Intent().apply {
                                        action = android.content.Intent.ACTION_SEND
                                        putExtra(android.content.Intent.EXTRA_TEXT, json)
                                        type = "text/plain"
                                    }
                                    context.startActivity(android.content.Intent.createChooser(sendIntent, "Share VPN Configuration"))
                                }
                            }
                        )
                    }

                    MainTab.TOOLS -> {
                        ToolsScreen(
                            activeProfile = activeProfile,
                            metrics = metrics,
                            isConnected = connectionState == com.example.model.VpnConnectionState.CONNECTED,
                            onOpenPayloadGenerator = { showPayloadDialog = true }
                        )
                    }

                    MainTab.LOGS -> {
                        LogsScreen(
                            logs = logs,
                            onClearLogs = { viewModel.clearLogs() }
                        )
                    }
                }
            }
        }
    }

    // Dialogs
    if (showAddEditDialog) {
        AddEditProfileDialog(
            initialProfile = editingProfile,
            onDismiss = { showAddEditDialog = false },
            onSave = { profile ->
                viewModel.saveProfile(profile)
                showAddEditDialog = false
                Toast.makeText(context, "Saved ${profile.name}", Toast.LENGTH_SHORT).show()
            }
        )
    }

    if (showImportDialog) {
        ImportConfigDialog(
            onDismiss = { showImportDialog = false },
            onImport = { rawText ->
                val count = viewModel.importConfigs(rawText)
                showImportDialog = false
                if (count > 0) {
                    Toast.makeText(context, "Imported $count VPN server(s) successfully!", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(context, "No valid VPN config found in text.", Toast.LENGTH_LONG).show()
                }
            }
        )
    }

    if (showPayloadDialog) {
        PayloadGeneratorDialog(
            onDismiss = { showPayloadDialog = false },
            onApplyPayload = { payload, bugHost ->
                showPayloadDialog = false
                // Create or update active profile with payload
                val current = activeProfile ?: VpnProfile(
                    name = "SSH + Custom Payload",
                    protocol = VpnProtocol.SSH,
                    server = "id-ssh.v2tunnel.net",
                    port = 443,
                    sshUsername = "vpnuser",
                    countryCode = "ID"
                )
                val updated = current.copy(
                    sni = bugHost,
                    sshPayload = payload,
                    protocol = if (current.protocol == VpnProtocol.SSH) VpnProtocol.SSH else current.protocol
                )
                viewModel.saveProfile(updated)
                Toast.makeText(context, "Applied payload and bug host ($bugHost) to profile!", Toast.LENGTH_SHORT).show()
            }
        )
    }

    if (showSettingsSheet) {
        SettingsSheet(
            selectedDns = selectedDns,
            onSelectDns = { viewModel.setDns(it) },
            isBypassLan = isBypassLan,
            onToggleBypassLan = { viewModel.toggleBypassLan(it) },
            isUdpForwarding = isUdpForwarding,
            onToggleUdpForwarding = { viewModel.toggleUdpForwarding(it) },
            isKillSwitch = isKillSwitch,
            onToggleKillSwitch = { viewModel.toggleKillSwitch(it) },
            onDismiss = { showSettingsSheet = false }
        )
    }
}
