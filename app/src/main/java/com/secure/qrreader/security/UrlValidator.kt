package com.secure.qrreader.security

import android.net.Uri
import android.util.Patterns
import java.net.IDN
import java.net.URL

/**
 * Security: Comprehensive URL validator for QR code content.
 * Prevents: XSS, Open Redirects, Phishing, Malicious URLs
 */
object UrlValidator {

    // Security: Allowed schemes
    private val ALLOWED_SCHEMES = setOf("http", "https")

    // Security: Blocked schemes that could be dangerous
    private val BLOCKED_SCHEMES = setOf(
        "javascript", "data", "vbscript", "file", "content",
        "intent", "sms", "tel", "mailto", "geo", "market"
    )

    // Security: Maximum URL length
    private const val MAX_URL_LENGTH = 2048

    // Security: Dangerous patterns
    private val DANGEROUS_PATTERNS = listOf(
        Regex("<script", RegexOption.IGNORE_CASE),
        Regex("javascript:", RegexOption.IGNORE_CASE),
        Regex("on\\w+\\s*=", RegexOption.IGNORE_CASE), // onclick=, onerror=, etc.
        Regex("data:text/html", RegexOption.IGNORE_CASE),
        Regex("\\.exe$", RegexOption.IGNORE_CASE),
        Regex("\\.bat$", RegexOption.IGNORE_CASE),
        Regex("\\.scr$", RegexOption.IGNORE_CASE),
        Regex("@"), // URL credential injection
    )

    // Security: Homoglyph characters that could be used for phishing
    private val HOMOGLYPH_CHARS = mapOf(
        'а' to 'a', 'е' to 'e', 'о' to 'o', 'р' to 'p', 'с' to 'c',
        'у' to 'y', 'х' to 'x', 'А' to 'A', 'В' to 'B', 'Е' to 'E',
        'К' to 'K', 'М' to 'M', 'Н' to 'H', 'О' to 'O', 'Р' to 'R',
        'С' to 'C', 'Т' to 'T', 'Х' to 'X'
    )

    data class ValidationResult(
        val isValid: Boolean,
        val sanitizedUrl: String?,
        val error: String? = null,
        val riskLevel: RiskLevel = RiskLevel.LOW
    )

    enum class RiskLevel {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    /**
     * Security: Validate and sanitize URL from QR code
     */
    fun validate(url: String): ValidationResult {
        // Check length
        if (url.length > MAX_URL_LENGTH) {
            return ValidationResult(
                isValid = false,
                sanitizedUrl = null,
                error = "URL exceeds maximum length",
                riskLevel = RiskLevel.HIGH
            )
        }

        // Check for dangerous patterns
        for (pattern in DANGEROUS_PATTERNS) {
            if (pattern.containsMatchIn(url)) {
                return ValidationResult(
                    isValid = false,
                    sanitizedUrl = null,
                    error = "URL contains dangerous pattern",
                    riskLevel = RiskLevel.CRITICAL
                )
            }
        }

        // Check for homoglyphs (phishing attempt)
        val hasHomoglyphs = url.any { it in HOMOGLYPH_CHARS.keys }
        if (hasHomoglyphs) {
            return ValidationResult(
                isValid = false,
                sanitizedUrl = null,
                error = "URL contains suspicious characters (possible phishing)",
                riskLevel = RiskLevel.HIGH
            )
        }

        // Parse URL
        val uri = try {
            Uri.parse(url)
        } catch (e: Exception) {
            return ValidationResult(
                isValid = false,
                sanitizedUrl = null,
                error = "Invalid URL format",
                riskLevel = RiskLevel.MEDIUM
            )
        }

        // Check scheme
        val scheme = uri.scheme?.lowercase()
        if (scheme == null || scheme !in ALLOWED_SCHEMES) {
            return if (scheme in BLOCKED_SCHEMES) {
                ValidationResult(
                    isValid = false,
                    sanitizedUrl = null,
                    error = "Blocked scheme: $scheme",
                    riskLevel = RiskLevel.CRITICAL
                )
            } else {
                ValidationResult(
                    isValid = false,
                    sanitizedUrl = null,
                    error = "Unsupported scheme: $scheme",
                    riskLevel = RiskLevel.MEDIUM
                )
            }
        }

        // Validate host
        val host = uri.host
        if (host.isNullOrBlank()) {
            return ValidationResult(
                isValid = false,
                sanitizedUrl = null,
                error = "Missing host",
                riskLevel = RiskLevel.HIGH
            )
        }

        // Check for IP address (potential phishing)
        if (isIpAddress(host)) {
            return ValidationResult(
                isValid = true,
                sanitizedUrl = url,
                error = "URL uses IP address instead of domain",
                riskLevel = RiskLevel.MEDIUM
            )
        }

        // Validate domain
        if (!isValidDomain(host)) {
            return ValidationResult(
                isValid = false,
                sanitizedUrl = null,
                error = "Invalid domain format",
                riskLevel = RiskLevel.HIGH
            )
        }

        // Check for URL shorteners (could hide malicious destination)
        if (isUrlShortener(host)) {
            return ValidationResult(
                isValid = true,
                sanitizedUrl = url,
                error = "URL shortener detected - destination hidden",
                riskLevel = RiskLevel.MEDIUM
            )
        }

        // Sanitize and return
        val sanitized = sanitizeUrl(url)
        return ValidationResult(
            isValid = true,
            sanitizedUrl = sanitized,
            riskLevel = if (hasHomoglyphs) RiskLevel.HIGH else RiskLevel.LOW
        )
    }

    /**
     * Security: Check if string is an IP address
     */
    private fun isIpAddress(host: String): Boolean {
        return Patterns.IP_ADDRESS.matcher(host).matches() ||
                host.contains(":") && host.split(":").size > 2 // IPv6
    }

    /**
     * Security: Validate domain format
     */
    private fun isValidDomain(domain: String): Boolean {
        if (domain.length > 253) return false

        return try {
            // Convert IDN to ASCII and validate
            val asciiDomain = IDN.toASCII(domain, IDN.ALLOW_UNASSIGNED)
            asciiDomain.matches(Regex("^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$"))
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Security: Check for known URL shorteners
     */
    private fun isUrlShortener(host: String): Boolean {
        val shorteners = setOf(
            "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly",
            "is.gd", "buff.ly", "adf.ly", "bit.do", "short.link"
        )
        return host in shorteners || host.endsWith(".short.link")
    }

    /**
     * Security: Sanitize URL by removing potential tracking parameters
     */
    fun sanitizeUrl(url: String): String {
        val uri = Uri.parse(url)

        // Security: Remove tracking parameters
        val paramsToRemove = setOf(
            "utm_source", "utm_medium", "utm_campaign",
            "utm_term", "utm_content", "fbclid", "gclid",
            "ref", "referrer", "source", "tracking_id"
        )

        val builder = uri.buildUpon().clearQuery()
        uri.queryParameterNames.forEach { paramName ->
            if (paramName.lowercase() !in paramsToRemove) {
                builder.appendQueryParameter(paramName, uri.getQueryParameter(paramName) ?: "")
            }
        }

        return builder.build().toString()
    }

    /**
     * Security: Get safe display version of URL
     */
    fun getDisplayUrl(url: String): String {
        return try {
            val uri = Uri.parse(url)
            val host = uri.host ?: return url

            // Show only host and path, remove query params for display
            "${uri.scheme}://$host${uri.path}"
        } catch (e: Exception) {
            url
        }
    }
}
