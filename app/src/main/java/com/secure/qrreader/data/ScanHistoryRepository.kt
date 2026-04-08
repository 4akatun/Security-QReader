package com.secure.qrreader.data

import android.content.Context
import android.net.Uri
import com.secure.qrreader.security.QrContentValidator
import com.secure.qrreader.security.UrlValidator
import org.json.JSONArray
import org.json.JSONObject

/**
 * Repository for managing scan history and security statistics.
 * Uses SecureStorage for encrypted persistence.
 */
class ScanHistoryRepository(context: Context) {

    private val secureStorage = com.secure.qrreader.security.SecureStorage.getInstance(context)

    companion object {
        private const val KEY_SCAN_HISTORY = "scan_history"
        private const val KEY_SECURITY_STATS = "security_stats"
        private const val MAX_HISTORY_SIZE = 100
    }

    /**
     * Add a new scan record to history.
     */
    fun addScanRecord(content: String, contentType: QrContentValidator.QrContentType, riskLevel: UrlValidator.RiskLevel, wasBlocked: Boolean) {
        val records = getScanRecords().toMutableList()

        val domain = if (riskLevel != UrlValidator.RiskLevel.LOW) {
            try {
                Uri.parse(content).host
            } catch (e: Exception) { null }
        } else null

        val record = ScanRecord(
            content = content,
            contentType = contentType.name,
            riskLevel = riskLevel.name,
            wasBlocked = wasBlocked,
            domain = domain
        )

        records.add(0, record) // Add to beginning

        // Trim to max size
        while (records.size > MAX_HISTORY_SIZE) {
            records.removeAt(records.size - 1)
        }

        saveScanRecords(records)
        updateSecurityStats(record)
    }

    /**
     * Get all scan records.
     */
    fun getScanRecords(): List<ScanRecord> {
        val json = secureStorage.getString(KEY_SCAN_HISTORY) ?: return emptyList()
        return try {
            val array = JSONArray(json)
            (0 until array.length()).map { i ->
                val obj = array.getJSONObject(i)
                ScanRecord(
                    id = obj.optLong("id", System.currentTimeMillis()),
                    content = obj.getString("content"),
                    contentType = obj.getString("contentType"),
                    riskLevel = obj.getString("riskLevel"),
                    timestamp = obj.optLong("timestamp", System.currentTimeMillis()),
                    wasBlocked = obj.optBoolean("wasBlocked", false),
                    domain = obj.optString("domain", "").takeIf { it.isNotEmpty() }
                )
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Get security statistics.
     */
    fun getSecurityStats(): SecurityStats {
        val json = secureStorage.getString(KEY_SECURITY_STATS) ?: return SecurityStats()
        return try {
            val obj = JSONObject(json)
            SecurityStats(
                totalScans = obj.optInt("totalScans", 0),
                safeScans = obj.optInt("safeScans", 0),
                blockedScans = obj.optInt("blockedScans", 0),
                warningScans = obj.optInt("warningScans", 0),
                lastScanTime = if (obj.has("lastScanTime")) obj.optLong("lastScanTime") else null,
                mostScannedDomain = obj.optString("mostScannedDomain", "").takeIf { it.isNotEmpty() }
            )
        } catch (e: Exception) {
            SecurityStats()
        }
    }

    /**
     * Clear all scan history.
     */
    fun clearHistory() {
        secureStorage.remove(KEY_SCAN_HISTORY)
        secureStorage.remove(KEY_SECURITY_STATS)
    }

    private fun saveScanRecords(records: List<ScanRecord>) {
        val array = JSONArray()
        records.forEach { record ->
            val obj = JSONObject().apply {
                put("id", record.id)
                put("content", record.content)
                put("contentType", record.contentType)
                put("riskLevel", record.riskLevel)
                put("timestamp", record.timestamp)
                put("wasBlocked", record.wasBlocked)
                put("domain", record.domain ?: "")
            }
            array.put(obj)
        }
        secureStorage.putString(KEY_SCAN_HISTORY, array.toString())
    }

    private fun updateSecurityStats(record: ScanRecord) {
        val currentStats = getSecurityStats()
        val domainCounts = mutableMapOf<String, Int>()
        getScanRecords().forEach { r ->
            r.domain?.let { domain ->
                domainCounts[domain] = (domainCounts[domain] ?: 0) + 1
            }
        }
        val mostScanned = domainCounts.maxByOrNull { it.value }?.key

        val newStats = JSONObject().apply {
            put("totalScans", currentStats.totalScans + 1)
            put("safeScans", currentStats.safeScans + if (record.riskLevel == "LOW") 1 else 0)
            put("blockedScans", currentStats.blockedScans + if (record.wasBlocked) 1 else 0)
            put("warningScans", currentStats.warningScans + if (record.riskLevel in listOf("MEDIUM", "HIGH")) 1 else 0)
            put("lastScanTime", System.currentTimeMillis())
            put("mostScannedDomain", mostScanned)
        }
        secureStorage.putString(KEY_SECURITY_STATS, newStats.toString())
    }
}