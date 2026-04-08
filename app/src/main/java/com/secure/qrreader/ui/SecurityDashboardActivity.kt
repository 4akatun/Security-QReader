package com.secure.qrreader.ui

import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import com.secure.qrreader.R
import com.secure.qrreader.data.ScanHistoryRepository
import com.secure.qrreader.data.ScanRecord
import com.secure.qrreader.databinding.ActivitySecurityDashboardBinding
import com.secure.qrreader.security.SecurityUtils

/**
 * Security Dashboard Activity showing scan history and security statistics.
 */
class SecurityDashboardActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySecurityDashboardBinding
    private lateinit var repository: ScanHistoryRepository
    private lateinit var historyAdapter: ScanHistoryAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySecurityDashboardBinding.inflate(layoutInflater)
        setContentView(binding.root)

        repository = ScanHistoryRepository(this)
        setupToolbar()
        setupRecyclerView()
        loadSecurityStats()
        loadEnvironmentStatus()
    }

    private fun setupToolbar() {
        binding.toolbar.setNavigationOnClickListener {
            finish()
        }
    }

    private fun setupRecyclerView() {
        historyAdapter = ScanHistoryAdapter()
        binding.recyclerHistory.apply {
            layoutManager = LinearLayoutManager(this@SecurityDashboardActivity)
            adapter = historyAdapter
        }

        binding.btnClearHistory.setOnClickListener {
            repository.clearHistory()
            loadSecurityStats()
        }
    }

    private fun loadSecurityStats() {
        val stats = repository.getSecurityStats()
        val records = repository.getScanRecords()

        // Update statistics
        binding.txtTotalScans.text = stats.totalScans.toString()
        binding.txtSafeScans.text = stats.safeScans.toString()
        binding.txtBlockedScans.text = stats.blockedScans.toString()
        binding.txtWarningScans.text = stats.warningScans.toString()

        // Update safety score
        val safetyPercentage = stats.getSafetyPercentage()
        binding.txtSafetyScore.text = "${safetyPercentage}%"
        binding.safetyProgress.progress = safetyPercentage

        // Update colors based on safety
        val scoreColor = when {
            safetyPercentage >= 80 -> R.color.success
            safetyPercentage >= 50 -> R.color.warning
            else -> R.color.error
        }
        binding.txtSafetyScore.setTextColor(ContextCompat.getColor(this, scoreColor))
        binding.safetyProgress.setIndicatorColor(ContextCompat.getColor(this, scoreColor))

        // Update description
        binding.txtSafetyDescription.text = when {
            stats.totalScans == 0 -> "No scans yet - stay safe!"
            stats.blockedScans == 0 && stats.warningScans == 0 -> "All scans were safe!"
            stats.blockedScans > 0 -> "${stats.blockedScans} dangerous URLs blocked"
            else -> "${stats.warningScans} URLs required caution"
        }

        // Update history list
        if (records.isEmpty()) {
            binding.recyclerHistory.visibility = View.GONE
            binding.txtEmptyHistory.visibility = View.VISIBLE
        } else {
            binding.recyclerHistory.visibility = View.VISIBLE
            binding.txtEmptyHistory.visibility = View.GONE
            historyAdapter.updateRecords(records)
        }
    }

    private fun loadEnvironmentStatus() {
        val status = SecurityUtils.getSecurityStatus(this)

        // Debugger status
        val isDebuggable = status["is_debuggable"] == true
        if (isDebuggable) {
            binding.indicatorDebugger.background.setTint(ContextCompat.getColor(this, R.color.warning))
            binding.txtDebuggerStatus.text = "Detected"
            binding.txtDebuggerStatus.setTextColor(ContextCompat.getColor(this, R.color.warning))
        } else {
            binding.indicatorDebugger.background.setTint(ContextCompat.getColor(this, R.color.success))
            binding.txtDebuggerStatus.text = "Not detected"
            binding.txtDebuggerStatus.setTextColor(ContextCompat.getColor(this, R.color.success))
        }

        // Emulator status
        val isEmulator = status["is_emulator"] == true
        if (isEmulator) {
            binding.indicatorEmulator.background.setTint(ContextCompat.getColor(this, R.color.warning))
            binding.txtEmulatorStatus.text = "Detected"
            binding.txtEmulatorStatus.setTextColor(ContextCompat.getColor(this, R.color.warning))
        } else {
            binding.indicatorEmulator.background.setTint(ContextCompat.getColor(this, R.color.success))
            binding.txtEmulatorStatus.text = "Not detected"
            binding.txtEmulatorStatus.setTextColor(ContextCompat.getColor(this, R.color.success))
        }

        // Installer status
        val isTrusted = status["is_trusted_installer"] == true
        if (isTrusted) {
            binding.indicatorInstaller.background.setTint(ContextCompat.getColor(this, R.color.success))
            binding.txtInstallerStatus.text = "Verified"
            binding.txtInstallerStatus.setTextColor(ContextCompat.getColor(this, R.color.success))
        } else {
            binding.indicatorInstaller.background.setTint(ContextCompat.getColor(this, R.color.error))
            binding.txtInstallerStatus.text = "Untrusted"
            binding.txtInstallerStatus.setTextColor(ContextCompat.getColor(this, R.color.error))
        }
    }
}