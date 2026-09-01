package com.example.parser

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import com.example.model.VpnProfile
import java.io.File
import java.io.FileOutputStream

/**
 * Exporter for exporting VPN configurations to .nikuvpn.tl files or shareable strings.
 */
object NikuVpnProfileExporter {

    /**
     * Exports a profile to JSON string formatted as .nikuvpn.tl
     */
    fun exportToJson(profile: VpnProfile): String {
        return NikuVpnProfileSerializer.serialize(profile)
    }

    /**
     * Creates a temporary .nikuvpn.tl file for sharing.
     */
    fun exportToFile(context: Context, profile: VpnProfile): File {
        val sanitizedName = profile.name
            .replace(Regex("[^a-zA-Z0-9._-]"), "_")
            .take(30)
            .ifBlank { "vpn_profile" }
        val fileName = "$sanitizedName${NikuVpnProfileSerializer.FILE_EXTENSION}"
        val exportDir = File(context.cacheDir, "exports").apply { mkdirs() }
        val file = File(exportDir, fileName)

        val content = exportToJson(profile)
        FileOutputStream(file).use { out ->
            out.write(content.toByteArray(Charsets.UTF_8))
            out.flush()
        }
        return file
    }

    /**
     * Creates an Intent to share the .nikuvpn.tl file via Android Share Sheet.
     */
    fun createShareFileIntent(context: Context, profile: VpnProfile): Intent {
        val file = exportToFile(context, profile)
        val uri: Uri = try {
            FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                file
            )
        } catch (e: Exception) {
            Uri.fromFile(file)
        }

        return Intent(Intent.ACTION_SEND).apply {
            type = "application/octet-stream"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "V2Tunnel Configuration - ${profile.name}")
            putExtra(Intent.EXTRA_TEXT, "Import this configuration into V2Tunnel (.nikuvpn.tl)\nProfile: ${profile.name}\nProtocol: ${profile.protocol.displayName}")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }
}
