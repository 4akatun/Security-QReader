package com.secure.qrreader.ui

import android.content.Context
import android.os.Build
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.secure.qrreader.R
import com.secure.qrreader.data.ScanRecord
import com.secure.qrreader.databinding.ItemScanHistoryBinding
import com.secure.qrreader.security.UrlValidator

/**
 * Adapter for displaying scan history in a RecyclerView.
 */
class ScanHistoryAdapter(
    private var records: List<ScanRecord> = emptyList()
) : RecyclerView.Adapter<ScanHistoryAdapter.ViewHolder>() {

    fun updateRecords(newRecords: List<ScanRecord>) {
        records = newRecords
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemScanHistoryBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(records[position])
    }

    override fun getItemCount(): Int = records.size

    inner class ViewHolder(private val binding: ItemScanHistoryBinding) : RecyclerView.ViewHolder(binding.root) {

        fun bind(record: ScanRecord) {
            val context = binding.root.context

            // Truncate content for display
            val displayContent = if (record.content.length > 50) {
                record.content.take(47) + "..."
            } else {
                record.content
            }
            binding.txtContent.text = displayContent
            binding.txtType.text = record.contentType
            binding.txtTime.text = record.getFormattedTime()

            // Set risk indicator color
            val riskColor = when (record.riskLevel) {
                "LOW" -> ContextCompat.getColor(context, R.color.success)
                "MEDIUM" -> ContextCompat.getColor(context, R.color.warning)
                "HIGH" -> ContextCompat.getColor(context, R.color.error)
                "CRITICAL" -> ContextCompat.getColor(context, R.color.critical)
                else -> ContextCompat.getColor(context, R.color.text_secondary)
            }
            binding.riskDot.background.setTint(riskColor)

            // Show blocked badge if applicable
            binding.txtBlockedBadge.visibility = if (record.wasBlocked) View.VISIBLE else View.GONE

            // Click to copy with security measures
            binding.root.setOnClickListener {
                copyToClipboardSecure(context, record.content)
            }
        }

        /**
         * Security: Copy content to clipboard with untrusted flag and auto-clear
         */
        private fun copyToClipboardSecure(context: Context, content: String) {
            try {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager

                val clip = android.content.ClipData.newPlainText("QR Content", content)

                // Security: Mark as untrusted on Android 13+
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    clip.description.extras = android.os.PersistableBundle().apply {
                        putBoolean("android.content.extra.IS_UNTRUSTED", true)
                    }
                }

                clipboard.setPrimaryClip(clip)

                // Security: Clear clipboard after 60 seconds for Android 14+ (best effort)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    binding.root.postDelayed({
                        try {
                            if (clipboard.hasPrimaryClip() &&
                                clipboard.primaryClip?.description?.toString()?.contains("QR Content") == true) {
                                clipboard.clearPrimaryClip()
                            }
                        } catch (e: Exception) {
                            // Ignore
                        }
                    }, 60000) // Clear after 60 seconds
                }

                Toast.makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(context, "Failed to copy", Toast.LENGTH_SHORT).show()
            }
        }
    }
}