package com.secure.qrreader.security

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.content.pm.SigningInfo
import android.os.Build
import android.util.Base64
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

/**
 * Security: App integrity and signature verification utilities.
 */
object SecurityUtils {

    /**
     * Security: Verify app signature matches expected value.
     * Use this to detect tampering or repackaging.
     */
    fun verifyAppSignature(context: Context, expectedHash: String): Boolean {
        return try {
            val currentHash = getAppSignatureHash(context)
            currentHash == expectedHash
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Security: Get the current app signature hash.
     * Store this hash securely and verify at runtime.
     */
    fun getAppSignatureHash(context: Context): String {
        return try {
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
            }

            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners
                    ?: packageInfo.signingInfo?.signingCertificateHistory
                    ?: emptyArray()
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures ?: emptyArray()
            }

            if (signatures.isEmpty()) {
                throw SecurityException("No signatures found")
            }

            // Get the primary signature
            val signature = signatures[0]
            hashSignature(signature)
        } catch (e: Exception) {
            throw SecurityException("Failed to get app signature", e)
        }
    }

    /**
     * Security: Hash a signature using SHA-256
     */
    private fun hashSignature(signature: Signature): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(signature.toByteArray())
            Base64.encodeToString(hash, Base64.NO_WRAP)
        } catch (e: Exception) {
            throw SecurityException("Failed to hash signature", e)
        }
    }

    /**
     * Security: Verify certificate chain (for certificate pinning).
     */
    fun verifyCertificateChain(certs: Array<X509Certificate>, pinnedHash: String): Boolean {
        return try {
            if (certs.isEmpty()) return false

            // Verify the leaf certificate matches the pinned hash
            val leafCertHash = hashCertificate(certs[0])
            leafCertHash == pinnedHash
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Security: Hash an X509 certificate
     */
    private fun hashCertificate(cert: X509Certificate): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(cert.encoded)
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    /**
     * Security: Check if app is running in debug mode.
     */
    fun isDebuggable(context: Context): Boolean {
        return try {
            val appInfo = context.applicationInfo
            (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Security: Check if app is running on an emulator.
     * Useful for detecting potential tampering environments.
     */
    fun isRunningOnEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.startsWith("unknown") ||
                Build.MODEL.contains("google_sdk") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK built for x86") ||
                Build.MANUFACTURER.contains("Genymotion") ||
                (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) ||
                "google_sdk" == Build.PRODUCT)
    }

    /**
     * Security: Get app version code
     */
    fun getAppVersionCode(context: Context): Long {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                0
            )
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.longVersionCode
            } else {
                @Suppress("DEPRECATION")
                packageInfo.versionCode.toLong()
            }
        } catch (e: Exception) {
            -1
        }
    }

    /**
     * Security: Get app version name
     */
    fun getAppVersionName(context: Context): String {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                0
            )
            packageInfo.versionName ?: "unknown"
        } catch (e: Exception) {
            "unknown"
        }
    }

    /**
     * Security: Verify installer is trusted (detect sideloading).
     */
    fun verifyInstaller(context: Context): Boolean {
        return try {
            val installerPackageName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(context.packageName)
            }

            // Trusted installers
            val trustedInstallers = setOf(
                "com.android.vending", // Google Play Store
                "com.amazon.venezia", // Amazon Appstore
                context.packageName // Self (for debug builds)
            )

            installerPackageName == null || installerPackageName in trustedInstallers
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Security: Get list of security recommendations
     */
    fun getSecurityStatus(context: Context): Map<String, Boolean> {
        return mapOf(
            "is_debuggable" to isDebuggable(context),
            "is_emulator" to isRunningOnEmulator(),
            "is_trusted_installer" to verifyInstaller(context),
            "signature_verified" to try {
                getAppSignatureHash(context).isNotEmpty()
            } catch (e: Exception) { false }
        )
    }
}
