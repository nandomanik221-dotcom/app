package com.example.ui.viewmodel

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.local.AppDatabase
import com.example.data.repository.VpnRepository
import com.example.model.DnsServer
import com.example.model.LogLevel
import com.example.model.VpnConnectionState
import com.example.model.VpnLogEntry
import com.example.model.VpnMetrics
import com.example.model.VpnProfile
import com.example.model.VpnProtocol
import com.example.parser.VpnConfigParser
import com.example.vpn.V2TunnelVpnService
import com.example.vpn.VpnController
import com.example.vpn.VpnLogManager
import com.example.vpn.VpnPingTester
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class VpnViewModel(
    private val repository: VpnRepository
) : ViewModel() {

    val profiles: StateFlow<List<VpnProfile>> = repository.allProfiles
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )

    val activeProfile: StateFlow<VpnProfile?> = VpnController.activeProfile
    val connectionState: StateFlow<VpnConnectionState> = VpnController.connectionState
    val metrics: StateFlow<VpnMetrics> = VpnController.metrics
    val logs: StateFlow<List<VpnLogEntry>> = VpnLogManager.logs

    private val _selectedFilter = MutableStateFlow<VpnProtocol?>(null)
    val selectedFilter: StateFlow<VpnProtocol?> = _selectedFilter.asStateFlow()

    private val _selectedDns = MutableStateFlow(DnsServer.PRESETS.first())
    val selectedDns: StateFlow<DnsServer> = _selectedDns.asStateFlow()

    private val _isBypassLan = MutableStateFlow(true)
    val isBypassLan: StateFlow<Boolean> = _isBypassLan.asStateFlow()

    private val _isUdpForwarding = MutableStateFlow(true)
    val isUdpForwarding: StateFlow<Boolean> = _isUdpForwarding.asStateFlow()

    private val _isKillSwitch = MutableStateFlow(false)
    val isKillSwitch: StateFlow<Boolean> = _isKillSwitch.asStateFlow()

    private val _isPingingAll = MutableStateFlow(false)
    val isPingingAll: StateFlow<Boolean> = _isPingingAll.asStateFlow()

    init {
        // Automatically select the first profile once available if none selected
        viewModelScope.launch {
            profiles.collect { list ->
                if (list.isNotEmpty() && VpnController.activeProfile.value == null) {
                    VpnController.setActiveProfile(list.first())
                }
            }
        }
    }

    fun setFilter(protocol: VpnProtocol?) {
        _selectedFilter.value = protocol
    }

    fun selectProfile(profile: VpnProfile) {
        VpnController.setActiveProfile(profile)
        VpnLogManager.log(LogLevel.INFO, "UI", "Selected profile: ${profile.name} (${profile.protocol.displayName})")
    }

    fun toggleConnection(context: Context, prepareLauncher: () -> Unit) {
        when (connectionState.value) {
            VpnConnectionState.DISCONNECTED, VpnConnectionState.ERROR -> {
                val intent = VpnService.prepare(context)
                if (intent != null) {
                    prepareLauncher()
                } else {
                    connectDirectly(context)
                }
            }
            VpnConnectionState.CONNECTED, VpnConnectionState.CONNECTING -> {
                disconnect(context)
            }
            else -> {}
        }
    }

    fun connectDirectly(context: Context) {
        val currentProfile = activeProfile.value
        if (currentProfile == null) {
            VpnLogManager.log(LogLevel.WARN, "UI", "Please select a VPN server profile first.")
            return
        }
        V2TunnelVpnService.startVpn(context, currentProfile.id)
    }

    fun disconnect(context: Context) {
        V2TunnelVpnService.stopVpn(context)
    }

    fun pingProfile(profile: VpnProfile) {
        viewModelScope.launch {
            val pingMs = VpnPingTester.ping(profile.server, profile.port)
            repository.updatePing(profile.id, pingMs)
            if (activeProfile.value?.id == profile.id) {
                VpnController.setActiveProfile(profile.copy(lastPingMs = pingMs))
            }
        }
    }

    fun pingAll() {
        viewModelScope.launch {
            _isPingingAll.value = true
            val currentList = profiles.value
            for (profile in currentList) {
                val pingMs = VpnPingTester.ping(profile.server, profile.port)
                repository.updatePing(profile.id, pingMs)
                if (activeProfile.value?.id == profile.id) {
                    VpnController.setActiveProfile(profile.copy(lastPingMs = pingMs))
                }
            }
            _isPingingAll.value = false
        }
    }

    fun importConfigs(rawText: String): Int {
        val parsed = VpnConfigParser.parse(rawText)
        if (parsed.isNotEmpty()) {
            viewModelScope.launch {
                repository.insertAll(parsed)
                if (activeProfile.value == null) {
                    VpnController.setActiveProfile(parsed.first())
                }
                VpnLogManager.log(LogLevel.INFO, "IMPORT", "Imported ${parsed.size} VPN configurations successfully.")
            }
        }
        return parsed.size
    }

    fun saveProfile(profile: VpnProfile) {
        viewModelScope.launch {
            if (profile.id == 0L) {
                val newId = repository.insert(profile)
                val saved = profile.copy(id = newId)
                VpnController.setActiveProfile(saved)
            } else {
                repository.update(profile)
                if (activeProfile.value?.id == profile.id) {
                    VpnController.setActiveProfile(profile)
                }
            }
        }
    }

    fun deleteProfile(profile: VpnProfile) {
        viewModelScope.launch {
            repository.delete(profile)
            if (activeProfile.value?.id == profile.id) {
                val remaining = profiles.value.filter { it.id != profile.id }
                VpnController.setActiveProfile(remaining.firstOrNull())
            }
        }
    }

    fun toggleFavorite(profile: VpnProfile) {
        viewModelScope.launch {
            repository.toggleFavorite(profile.id, !profile.isFavorite)
        }
    }

    fun setDns(dns: DnsServer) {
        _selectedDns.value = dns
        VpnLogManager.log(LogLevel.INFO, "DNS", "DNS updated to: ${dns.name} (${dns.primaryIp})")
    }

    fun toggleBypassLan(value: Boolean) {
        _isBypassLan.value = value
    }

    fun toggleUdpForwarding(value: Boolean) {
        _isUdpForwarding.value = value
    }

    fun toggleKillSwitch(value: Boolean) {
        _isKillSwitch.value = value
    }

    fun clearLogs() {
        VpnLogManager.clear()
    }
}
