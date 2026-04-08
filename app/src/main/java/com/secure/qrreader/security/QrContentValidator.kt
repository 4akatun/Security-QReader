package com.secure.qrreader.security

import android.content.Intent
import android.net.Uri
import com.secure.qrreader.security.UrlValidator.RiskLevel

/**
 * Security: Comprehensive QR content validator.
 * Handles all QR content types securely.
 */
object QrContentValidator {

    enum class QrContentType {
        URL,
        TEXT,
        EMAIL,
        PHONE,
        SMS,
        CONTACT,
        WIFI,
        CALENDAR,
        GEO,
        PRODUCT,
        UNKNOWN
    }

    data class QrValidationResult(
        val contentType: QrContentType,
        val rawContent: String,
        val sanitizedContent: String?,
        val isValid: Boolean,
        val riskLevel: RiskLevel,
        val warning: String? = null,
        val intent: Intent? = null
    )

    // Security: Maximum content length
    private const val MAX_CONTENT_LENGTH = 4096

    // Security: Dangerous content patterns
    private val DANGEROUS_PATTERNS = listOf(
        Regex("^[A-Z0-9]{50,}$"), // Potential encryption key or hash
        Regex("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"), // Email
        Regex("tel:\\+?[0-9\\-\\s()]+"), // Phone
        Regex("sms:\\+?[0-9\\-\\s()]+"), // SMS
    )

    /**
     * Security: Validate and classify QR content
     */
    fun validate(content: String): QrValidationResult {
        // Check length
        if (content.length > MAX_CONTENT_LENGTH) {
            return QrValidationResult(
                contentType = QrContentType.UNKNOWN,
                rawContent = content,
                sanitizedContent = null,
                isValid = false,
                riskLevel = RiskLevel.HIGH,
                warning = "Content exceeds maximum length"
            )
        }

        // Detect content type
        val contentType = detectContentType(content)

        // Validate based on type
        return when (contentType) {
            QrContentType.URL -> validateUrl(content)
            QrContentType.TEXT -> validateText(content)
            QrContentType.EMAIL -> validateEmail(content)
            QrContentType.PHONE -> validatePhone(content)
            QrContentType.SMS -> validateSms(content)
            QrContentType.WIFI -> validateWifi(content)
            QrContentType.CONTACT -> validateContact(content)
            else -> QrValidationResult(
                contentType = contentType,
                rawContent = content,
                sanitizedContent = content,
                isValid = true,
                riskLevel = RiskLevel.LOW
            )
        }
    }

    /**
     * Security: Detect QR content type
     */
    private fun detectContentType(content: String): QrContentType {
        return when {
            // URL patterns
            content.startsWith("http://", ignoreCase = true) ||
            content.startsWith("https://", ignoreCase = true) ||
            content.startsWith("www.") -> QrContentType.URL

            // Email (MATMSG or MAILTO)
            content.startsWith("MATMSG:", ignoreCase = true) ||
            content.startsWith("mailto:", ignoreCase = true) ||
            content.contains("@") && content.contains(".") -> QrContentType.EMAIL

            // Phone
            content.startsWith("tel:", ignoreCase = true) -> QrContentType.PHONE

            // SMS
            content.startsWith("sms:", ignoreCase = true) ||
            content.startsWith("SMSTO:", ignoreCase = true) -> QrContentType.SMS

            // WiFi
            content.startsWith("WIFI:", ignoreCase = true) -> QrContentType.WIFI

            // Contact (MECARD or VCARD)
            content.startsWith("MECARD:", ignoreCase = true) ||
            content.startsWith("BEGIN:VCARD", ignoreCase = true) -> QrContentType.CONTACT

            // Calendar
            content.startsWith("BEGIN:VEVENT", ignoreCase = true) -> QrContentType.CALENDAR

            // Geo location
            content.startsWith("geo:", ignoreCase = true) ||
            content.startsWith("google maps:", ignoreCase = true) -> QrContentType.GEO

            // Product
            content.startsWith("0", ignoreCase = true) && content.length in 8..14 -> QrContentType.PRODUCT

            else -> QrContentType.TEXT
        }
    }

    private fun validateUrl(content: String): QrValidationResult {
        val urlResult = UrlValidator.validate(content)

        val intent = if (urlResult.isValid && urlResult.sanitizedUrl != null) {
            Intent(Intent.ACTION_VIEW).apply {
                data = Uri.parse(urlResult.sanitizedUrl)
            }
        } else null

        return QrValidationResult(
            contentType = QrContentType.URL,
            rawContent = content,
            sanitizedContent = urlResult.sanitizedUrl,
            isValid = urlResult.isValid,
            riskLevel = urlResult.riskLevel,
            warning = urlResult.error,
            intent = intent
        )
    }

    private fun validateText(content: String): QrValidationResult {
        // Check for potentially dangerous text content
        val hasSuspiciousContent = DANGEROUS_PATTERNS.any { it.matches(content) }

        return QrValidationResult(
            contentType = QrContentType.TEXT,
            rawContent = content,
            sanitizedContent = content,
            isValid = true,
            riskLevel = if (hasSuspiciousContent) RiskLevel.MEDIUM else RiskLevel.LOW,
            warning = if (hasSuspiciousContent) "Text contains suspicious patterns" else null
        )
    }

    private fun validateEmail(content: String): QrValidationResult {
        val emailPattern = Regex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
        val isValid = emailPattern.containsMatchIn(content)

        val intent = if (isValid) {
            Intent(Intent.ACTION_SENDTO).apply {
                data = Uri.parse("mailto:")
                putExtra(Intent.EXTRA_EMAIL, arrayOf(content.replace("mailto:", "", ignoreCase = true)))
            }
        } else null

        return QrValidationResult(
            contentType = QrContentType.EMAIL,
            rawContent = content,
            sanitizedContent = content,
            isValid = isValid,
            riskLevel = if (isValid) RiskLevel.LOW else RiskLevel.MEDIUM,
            intent = intent
        )
    }

    private fun validatePhone(content: String): QrValidationResult {
        val phonePattern = Regex("\\+?[0-9\\-\\s()]{7,}")
        val phone = content.replace("tel:", "", ignoreCase = true).trim()
        val isValid = phonePattern.matches(phone)

        return QrValidationResult(
            contentType = QrContentType.PHONE,
            rawContent = content,
            sanitizedContent = phone,
            isValid = isValid,
            riskLevel = if (isValid) RiskLevel.LOW else RiskLevel.MEDIUM,
            warning = if (!isValid) "Invalid phone number format" else null
        )
    }

    private fun validateSms(content: String): QrValidationResult {
        val smsContent = content.replace(Regex("^(sms:|SMSTO:)", RegexOption.IGNORE_CASE), "").trim()
        val phonePattern = Regex("\\+?[0-9\\-\\s()]{7,}")

        return QrValidationResult(
            contentType = QrContentType.SMS,
            rawContent = content,
            sanitizedContent = smsContent,
            isValid = phonePattern.containsMatchIn(smsContent),
            riskLevel = RiskLevel.LOW,
            warning = "SMS will be sent to: $smsContent"
        )
    }

    private fun validateWifi(content: String): QrValidationResult {
        // WIFI:S=MySSID;T=WPA;P=mypassword;;
        val isValid = content.contains("S=", ignoreCase = true) &&
                     content.contains("T=", ignoreCase = true)

        return QrValidationResult(
            contentType = QrContentType.WIFI,
            rawContent = content,
            sanitizedContent = content,
            isValid = isValid,
            riskLevel = RiskLevel.LOW,
            warning = if (isValid) "This will connect to a WiFi network" else null
        )
    }

    private fun validateContact(content: String): QrValidationResult {
        return QrValidationResult(
            contentType = QrContentType.CONTACT,
            rawContent = content,
            sanitizedContent = content,
            isValid = true,
            riskLevel = RiskLevel.LOW,
            warning = "This will add a contact to your device"
        )
    }
}
