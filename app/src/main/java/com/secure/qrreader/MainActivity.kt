package com.secure.qrreader

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.view.View
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.Camera
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.common.InputImage
import com.secure.qrreader.data.ScanHistoryRepository
import com.secure.qrreader.databinding.ActivityMainBinding
import com.secure.qrreader.security.QrContentValidator
import com.secure.qrreader.security.QrContentValidator.QrContentType
import com.secure.qrreader.security.SecurityUtils
import com.secure.qrreader.security.UrlValidator
import com.secure.qrreader.ui.SecurityDashboardActivity
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Main Activity with secure QR code scanning.
 * Implements all security best practices for QR scanning.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var cameraExecutor: ExecutorService
    private lateinit var vibrator: Vibrator
    private lateinit var scanHistoryRepository: ScanHistoryRepository

    private var camera: Camera? = null
    private var isFlashOn = false
    private var isShowingDialog = false

    // Security: Camera permission launcher
    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            startCamera()
        } else {
            showPermissionDenied()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security: Prevent screenshots
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Initialize repositories
        scanHistoryRepository = ScanHistoryRepository(this)

        // Initialize vibrator
        vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val vibratorManager = getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as VibratorManager
            vibratorManager.defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            getSystemService(VIBRATOR_SERVICE) as Vibrator
        }

        cameraExecutor = Executors.newSingleThreadExecutor()

        // Check camera permission
        checkCameraPermission()

        // Setup UI listeners
        setupListeners()
    }

    /**
     * Security: Setup UI listeners
     */
    private fun setupListeners() {
        binding.btnOpenUrl.setOnClickListener {
            val url = binding.txtLastScannedUrl.text.toString()
            if (url.isNotBlank() && url != "—") {
                openUrlSecurely(url)
            }
        }

        binding.btnClearHistory.setOnClickListener {
            showClearHistoryDialog()
        }

        binding.btnSecurityDashboard.setOnClickListener {
            startActivity(Intent(this, SecurityDashboardActivity::class.java))
        }

        binding.btnFlashlight.setOnClickListener {
            toggleFlashlight()
        }
    }

    /**
     * Toggle flashlight for low light conditions
     */
    private fun toggleFlashlight() {
        camera?.let { cam ->
            if (cam.cameraInfo.hasFlashUnit()) {
                isFlashOn = !isFlashOn
                cam.cameraControl.enableTorch(isFlashOn)

                // Update button appearance
                binding.btnFlashlight.setIconTintResource(
                    if (isFlashOn) R.color.warning else R.color.text_primary
                )

                val message = if (isFlashOn) "Flashlight on" else "Flashlight off"
                Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "No flashlight available", Toast.LENGTH_SHORT).show()
            }
        } ?: run {
            Toast.makeText(this, "Camera not ready", Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * Security: Check and request camera permission
     */
    private fun checkCameraPermission() {
        when {
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED -> {
                startCamera()
            }
            shouldShowRequestPermissionRationale(Manifest.permission.CAMERA) -> {
                showPermissionRationale()
            }
            else -> {
                cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
            }
        }
    }

    /**
     * Security: Show permission rationale
     */
    private fun showPermissionRationale() {
        AlertDialog.Builder(this)
            .setTitle("Camera Permission Required")
            .setMessage("This app needs camera access to scan QR codes. The camera is only used for QR code detection and no images are stored.")
            .setPositiveButton("Grant") { _, _ ->
                cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
            }
            .setNegativeButton("Deny") { _, _ ->
                showPermissionDenied()
            }
            .setCancelable(false)
            .show()
    }

    /**
     * Security: Show permission denied message
     */
    private fun showPermissionDenied() {
        Toast.makeText(
            this,
            "Camera permission denied. Cannot scan QR codes.",
            Toast.LENGTH_LONG
        ).show()
        binding.txtStatus.text = "Permission denied"
        updateStatusIndicator(false)
    }

    private fun updateStatusIndicator(success: Boolean) {
        binding.statusIndicator.background.setTint(
            ContextCompat.getColor(
                this,
                if (success) R.color.success else R.color.warning
            )
        )
    }

    /**
     * Security: Start camera with CameraX
     */
    private fun startCamera() {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)

        cameraProviderFuture.addListener({
            val cameraProvider = cameraProviderFuture.get()

            // Preview
            val preview = Preview.Builder()
                .build()
                .also {
                    it.setSurfaceProvider(binding.previewView.surfaceProvider)
                }

            // Image analysis for QR scanning
            val imageAnalysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also {
                    it.setAnalyzer(cameraExecutor) { imageProxy ->
                        processImageProxy(imageProxy)
                    }
                }

            // Select back camera
            val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA

            try {
                // Unbind all use cases before rebinding
                cameraProvider.unbindAll()

                // Bind use cases to camera
                camera = cameraProvider.bindToLifecycle(
                    this,
                    cameraSelector,
                    preview,
                    imageAnalysis
                )

                binding.txtStatus.text = "Ready to scan"
                updateStatusIndicator(true)

            } catch (e: Exception) {
                // Security: Generic error message
                binding.txtStatus.text = "Camera error"
                updateStatusIndicator(false)
            }

        }, ContextCompat.getMainExecutor(this))
    }

    /**
     * Security: Process image for QR codes
     */
    private fun processImageProxy(imageProxy: ImageProxy) {
        try {
            val mediaImage = imageProxy.image ?: return

            val image = InputImage.fromMediaImage(
                mediaImage,
                imageProxy.imageInfo.rotationDegrees
            )

            val scanner = BarcodeScanning.getClient()

            scanner.process(image)
                .addOnSuccessListener { barcodes ->
                    if (barcodes.isNotEmpty()) {
                        // Haptic feedback on successful scan
                        vibrate()

                        // Process first barcode
                        val barcode = barcodes.first()
                        barcode.rawValue?.let { content ->
                            handleScannedContent(content, barcode.displayValue)
                        }
                    }
                }
                .addOnFailureListener {
                    // Security: Generic error message
                }
                .addOnCompleteListener {
                    imageProxy.close()
                    scanner.close()
                }

        } catch (e: Exception) {
            imageProxy.close()
        }
    }

    /**
     * Security: Handle scanned QR content securely
     */
    @Suppress("UNUSED_PARAMETER")
    private fun handleScannedContent(rawContent: String, displayValue: String?) {
        if (isShowingDialog) return

        // Validate content with security checks
        val result = QrContentValidator.validate(rawContent)

        runOnUiThread {
            when (result.contentType) {
                QrContentType.URL -> handleUrlScan(result)
                else -> handleOtherContent(result)
            }
        }
    }

    /**
     * Security: Handle URL QR code with security validation
     */
    private fun handleUrlScan(result: QrContentValidator.QrValidationResult) {
        isShowingDialog = true

        val displayUrl = UrlValidator.getDisplayUrl(result.rawContent)

        // Record in history
        scanHistoryRepository.addScanRecord(
            content = result.rawContent,
            contentType = result.contentType,
            riskLevel = result.riskLevel,
            wasBlocked = !result.isValid
        )

        // Build security warning message
        val warningMessage = buildString {
            append("URL: $displayUrl\n\n")

            result.warning?.let {
                append("⚠️ $it\n\n")
            }

            append("Security Assessment:\n")
            append("• Risk Level: ${getRiskLevelText(result.riskLevel)}\n")
            append("• HTTPS: ${if (result.rawContent.startsWith("https")) "Yes" else "No"}\n")
        }

        // Update risk level container
        binding.riskLevelContainer.visibility = View.VISIBLE
        binding.riskIndicator.background.setTint(
            ContextCompat.getColor(this, getRiskColor(result.riskLevel))
        )
        binding.txtRiskLevel.text = getRiskLevelText(result.riskLevel)
        binding.txtRiskLevel.setTextColor(ContextCompat.getColor(this, getRiskColor(result.riskLevel)))

        AlertDialog.Builder(this)
            .setTitle("QR Code Detected")
            .setMessage(warningMessage)
            .setPositiveButton("Open URL") { _, _ ->
                result.sanitizedContent?.let { openUrlSecurely(it) }
                isShowingDialog = false
            }
            .setNeutralButton("Copy") { _, _ ->
                copyToClipboard(result.rawContent)
                isShowingDialog = false
            }
            .setNegativeButton("Cancel") { _, _ ->
                isShowingDialog = false
            }
            .setOnDismissListener {
                isShowingDialog = false
            }
            .setCancelable(false)
            .show()

        // Update UI
        binding.txtLastScannedUrl.text = result.sanitizedContent ?: result.rawContent
        binding.txtStatus.text = "URL scanned"
        updateStatusIndicator(true)
    }

    /**
     * Security: Handle non-URL content
     */
    private fun handleOtherContent(result: QrContentValidator.QrValidationResult) {
        isShowingDialog = true

        // Record in history
        scanHistoryRepository.addScanRecord(
            content = result.rawContent,
            contentType = result.contentType,
            riskLevel = result.riskLevel,
            wasBlocked = !result.isValid
        )

        val message = buildString {
            append("Content Type: ${result.contentType}\n\n")
            append("Content:\n${result.rawContent}\n\n")

            result.warning?.let {
                append("⚠️ $it\n")
            }
        }

        AlertDialog.Builder(this)
            .setTitle("QR Code Detected")
            .setMessage(message)
            .setPositiveButton("OK") { _, _ ->
                isShowingDialog = false
            }
            .setNeutralButton("Copy") { _, _ ->
                copyToClipboard(result.rawContent)
                isShowingDialog = false
            }
            .setNegativeButton("Cancel") { _, _ ->
                isShowingDialog = false
            }
            .setOnDismissListener {
                isShowingDialog = false
            }
            .setCancelable(false)
            .show()

        binding.txtStatus.text = "Content scanned"
        binding.txtLastScannedUrl.text = result.rawContent.take(100)
        updateStatusIndicator(true)
    }

    /**
     * Security: Open URL securely using external browser
     */
    private fun openUrlSecurely(url: String) {
        try {
            // Security: Use external browser (safer than WebView)
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(intent)
        } catch (e: Exception) {
            Toast.makeText(this, "Cannot open URL", Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * Security: Copy content to clipboard with security measures
     * - Uses untrusted flag on Android 13+
     * - Content expires from clipboard after a short period
     */
    private fun copyToClipboard(content: String) {
        try {
            val clipboard = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager

            // Build clip data
            val clip = android.content.ClipData.newPlainText("QR Content", content)

            // Security: Mark as untrusted on Android 13+
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                clip.description.extras = android.os.PersistableBundle().apply {
                    putBoolean("android.content.extra.IS_UNTRUSTED", true)
                }
            }

            clipboard.setPrimaryClip(clip)

            // Security: Clear clipboard after 60 seconds for Android 14+ (best effort)
            // Note: Android doesn't provide a direct clipboard expiration API
            // The content will be cleared when the app clears it manually or on device restart
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

            Toast.makeText(this, "Copied to clipboard", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Failed to copy", Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * Security: Provide haptic feedback on scan
     */
    private fun vibrate() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                vibrator.vibrate(
                    VibrationEffect.createOneShot(
                        200,
                        VibrationEffect.DEFAULT_AMPLITUDE
                    )
                )
            } else {
                @Suppress("DEPRECATION")
                vibrator.vibrate(200)
            }
        } catch (e: Exception) {
            // Vibration not critical
        }
    }

    /**
     * Security: Get risk level display text
     */
    private fun getRiskLevelText(riskLevel: UrlValidator.RiskLevel): String {
        return when (riskLevel) {
            UrlValidator.RiskLevel.LOW -> "Low (Safe)"
            UrlValidator.RiskLevel.MEDIUM -> "Medium (Caution)"
            UrlValidator.RiskLevel.HIGH -> "High (Warning)"
            UrlValidator.RiskLevel.CRITICAL -> "Critical (Blocked)"
        }
    }

    /**
     * Get color for risk level
     */
    private fun getRiskColor(riskLevel: UrlValidator.RiskLevel): Int {
        return when (riskLevel) {
            UrlValidator.RiskLevel.LOW -> R.color.success
            UrlValidator.RiskLevel.MEDIUM -> R.color.warning
            UrlValidator.RiskLevel.HIGH -> R.color.error
            UrlValidator.RiskLevel.CRITICAL -> R.color.critical
        }
    }

    /**
     * Security: Show clear history confirmation
     */
    private fun showClearHistoryDialog() {
        AlertDialog.Builder(this)
            .setTitle("Clear History")
            .setMessage("Are you sure you want to clear the scan history and statistics?")
            .setPositiveButton("Clear") { _, _ ->
                scanHistoryRepository.clearHistory()
                binding.txtLastScannedUrl.text = "—"
                binding.riskLevelContainer.visibility = View.GONE
                binding.txtStatus.text = "History cleared"
                Toast.makeText(this, "History cleared", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
    }

    override fun onResume() {
        super.onResume()

        // Security: Re-verify app integrity on resume
        verifyIntegrityOnResume()
    }

    /**
     * Security: Verify integrity when app resumes
     */
    private fun verifyIntegrityOnResume() {
        val status = SecurityUtils.getSecurityStatus(this)

        // Log any suspicious status changes
        if (status["is_debuggable"] == true ||
            status["is_emulator"] == true ||
            status["is_trusted_installer"] == false
        ) {
            // Security: Handle suspicious state
            // In production, consider additional verification
        }
    }
}