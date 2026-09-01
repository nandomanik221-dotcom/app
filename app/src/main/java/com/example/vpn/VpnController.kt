package com.example.vpn

import com.example.model.LogLevel
import com.example.model.VpnConnectionState
import com.example.model.VpnLogEntry
import com.example.model.VpnMetrics
import com.example.model.VpnProfile
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

object VpnLogManager {
    private val _logs = MutableStateFlow<List<VpnLogEntry>>(emptyList())
    val logs: StateFlow<List<VpnLogEntry>> = _logs.asStateFlow()

    fun log(level: LogLevel, tag: String, message: String) {
        val entry = VpnLogEntry(
            timestamp = System.currentTimeMillis(),
            level = level,
            tag = tag,
            message = message
        )
        _logs.update { current ->
            (current + entry).takeLast(300)
        }
    }

    fun clear() {
        _logs.value = emptyList()
    }
}

object VpnController {
    private val scope = CoroutineScope(Dispatchers.Main)

    private val _connectionState = MutableStateFlow(VpnConnectionState.DISCONNECTED)
    val connectionState: StateFlow<VpnConnectionState> = _connectionState.asStateFlow()

    private val _activeProfile = MutableStateFlow<VpnProfile?>(null)
    val activeProfile: StateFlow<VpnProfile?> = _activeProfile.asStateFlow()

    private val _metrics = MutableStateFlow(VpnMetrics())
    val metrics: StateFlow<VpnMetrics> = _metrics.asStateFlow()

    fun setConnectionState(state: VpnConnectionState) {
        _connectionState.value = state
    }

    fun setActiveProfile(profile: VpnProfile?) {
        _activeProfile.value = profile
    }

    fun updateMetrics(transform: (VpnMetrics) -> VpnMetrics) {
        _metrics.update(transform)
    }

    fun resetMetrics() {
        _metrics.value = VpnMetrics()
    }
}
