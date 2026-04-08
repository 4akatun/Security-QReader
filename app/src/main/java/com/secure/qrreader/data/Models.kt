package com.secure.qrreader.data

import com.secure.qrreader.security.UrlValidator

/**
 * Represents a single scan record in history.
 */
data class ScanRecord(
    val id: Long = System.currentTimeMillis(),
    val content: String,
    val contentType: String,
    val riskLevel: String,
    val timestamp: Long = System.currentTimeMillis(),
    val wasBlocked: Boolean = false,
    val domain: String? = null
) {
    fun getFormattedTime(): String {
        val sdf = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
        return sdf.format(java.util.Date(timestamp))
    }

    fun getFormattedDate(): String {
        val sdf = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.getDefault())
        return sdf.format(java.util.Date(timestamp))
    }
}

/**
 * Security statistics for the dashboard.
 */
data class SecurityStats(
    val totalScans: Int = 0,
    val safeScans: Int = 0,
    val blockedScans: Int = 0,
    val warningScans: Int = 0,
    val lastScanTime: Long? = null,
    val mostScannedDomain: String? = null
) {
    fun getSafetyPercentage(): Int {
        return if (totalScans > 0) ((safeScans.toFloat() / totalScans) * 100).toInt() else 100
    }
}