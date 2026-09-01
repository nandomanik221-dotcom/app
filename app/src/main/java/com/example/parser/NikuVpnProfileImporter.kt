package com.example.parser

import android.content.Context
import android.net.Uri
import com.example.model.VpnProfile
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Importer for reading and parsing .nikuvpn.tl files or raw configuration text.
 */
object NikuVpnProfileImporter {

    /**
     * Imports profiles from a raw text payload (either .nikuvpn.tl JSON or legacy URIs).
     */
    fun importFromText(text: String): List<VpnProfile> {
        val trimmed = text.trim()
        if (trimmed.isBlank()) return emptyList()

        // 1. Check if it's a .nikuvpn.tl single JSON or JSON array
        if (NikuVpnProfileSerializer.isNikuVpnConfig(trimmed)) {
            val single = NikuVpnProfileSerializer.deserialize(trimmed)
            if (single != null) return listOf(single)
        }

        // 2. Fallback to line-by-line / URI parser
        return VpnConfigParser.parse(trimmed)
    }

    /**
     * Imports a profile from a content Uri (e.g. from File Picker or file intent).
     */
    fun importFromUri(context: Context, uri: Uri): List<VpnProfile> {
        return try {
            val inputStream = context.contentResolver.openInputStream(uri) ?: return emptyList()
            val text = BufferedReader(InputStreamReader(inputStream, Charsets.UTF_8)).use { it.readText() }
            importFromText(text)
        } catch (e: Exception) {
            emptyList()
        }
    }
}
