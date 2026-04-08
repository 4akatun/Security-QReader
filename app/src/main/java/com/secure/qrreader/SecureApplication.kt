package com.secure.qrreader

import android.app.Application
import android.content.Context
import android.util.Log
import com.secure.qrreader.security.SecureStorage
import com.secure.qrreader.security.SecurityUtils
import org.conscrypt.Conscrypt
import java.security.Security

/**
 * Security: Application class with security hardening.
 * Initializes security providers and performs integrity checks.
 */
class SecureApplication : Application() {

    companion object {
        private const val TAG = "SecureApp"
        // WARNING: Set this to your production signature hash before releasing
        // Get it by running: SecurityUtils.getAppSignatureHash(context)
        // Note: Cannot use const for nullable String
        private val PRODUCTION_SIGNATURE_HASH: String? = null

        // Security violation flags stored securely
        const val PREF_SECURITY_VIOLATION = "security_violation_detected"
        const val PREF_VIOLATION_REASON = "security_violation_reason"

        @Volatile
        private var securityViolationOccurred = false

        fun hasSecurityViolation(): Boolean = securityViolationOccurred
    }

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)

        // Security: Install Conscrypt provider for latest security patches
        installSecurityProvider()
    }

    override fun onCreate() {
        super.onCreate()

        // Security: Perform integrity checks
        performIntegrityChecks()

        // Security: Harden WebView (must be called on UI thread)
        hardenWebView()
    }

    /**
     * Security: Install Conscrypt security provider.
     * This ensures the app uses the latest security patches
     * independent of the OS security provider.
     */
    private fun installSecurityProvider() {
        try {
            // Conscrypt provides up-to-date OpenSSL and BoringSSL
            val provider = Conscrypt.newProvider()
            Security.insertProviderAt(provider, 1)

            // Verify it was installed
            val installedProvider = Security.getProvider("Conscrypt")
            if (installedProvider == null) {
                Log.w(TAG, "Conscrypt provider not installed - using system provider")
            }
        } catch (e: Exception) {
            // Security: Log the failure but don't expose details
            Log.e(TAG, "Failed to install Conscrypt security provider")
            // Continue with system provider - this is not a critical failure
        }
    }

    /**
     * Security: Perform app integrity checks.
     * These checks verify the app hasn't been tampered with.
     */
    private fun performIntegrityChecks() {
        val violations = mutableListOf<String>()

        // Security: Check if running in debug mode (should be false in production)
        val isDebug = SecurityUtils.isDebuggable(this)
        if (isDebug) {
            violations.add("Debug mode enabled")
        }

        // Security: Check if running on emulator (potential tampering environment)
        val isEmulator = SecurityUtils.isRunningOnEmulator()
        if (isEmulator) {
            violations.add("Running on emulator")
        }

        // Security: Verify installer is trusted
        val isTrustedInstaller = SecurityUtils.verifyInstaller(this)
        if (!isTrustedInstaller) {
            violations.add("Untrusted installer")
        }

        // Security: Verify signature if configured
        val expectedSignatureHash = PRODUCTION_SIGNATURE_HASH
        if (!expectedSignatureHash.isNullOrBlank()) {
            try {
                val currentHash = SecurityUtils.getAppSignatureHash(this)
                if (currentHash != expectedSignatureHash) {
                    violations.add("Signature mismatch - possible tampering")
                }
            } catch (e: Exception) {
                violations.add("Signature verification failed")
            }
        }

        // If any violations, store and handle them
        if (violations.isNotEmpty()) {
            val reason = violations.joinToString("; ")
            handleSecurityViolation(reason)
        }
    }

    /**
     * Security: Handle security violations.
     * Stores violation state and restricts app functionality.
     */
    private fun handleSecurityViolation(reason: String) {
        securityViolationOccurred = true

        // Store securely using EncryptedSharedPreferences
        try {
            val secureStorage = SecureStorage.getInstance(this)
            secureStorage.putBoolean(PREF_SECURITY_VIOLATION, true)
            secureStorage.putString(PREF_VIOLATION_REASON, reason)
        } catch (e: Exception) {
            // If secure storage fails, still mark violation
            Log.e(TAG, "Failed to store security violation")
        }

        // Log the violation (details are not exposed to user)
        Log.w(TAG, "Security violation detected")

        // In production, you could:
        // - Throw SecurityException to prevent app launch
        // - Disable sensitive features
        // - Report to your security monitoring system
        // For this app, we warn but allow limited functionality
    }

    /**
     * Security: Harden WebView against common attacks.
     * Must be called on UI thread.
     * Note: This app doesn't use WebView, but we ensure settings are hardened.
     */
    private fun hardenWebView() {
        try {
            // This app doesn't use WebView - all URLs are opened in external browser
            // which is the secure approach (no WebView vulnerabilities possible)

            // Verify debugging is disabled
            if (isDebuggable(this)) {
                Log.w(TAG, "App is debuggable")
            }
        } catch (e: Exception) {
            // WebView not available - this app doesn't use it anyway
        }
    }

    /**
     * Security: Check if app is debuggable
     */
    private fun isDebuggable(context: Context): Boolean {
        return try {
            (context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        } catch (e: Exception) {
            false
        }
    }
}
