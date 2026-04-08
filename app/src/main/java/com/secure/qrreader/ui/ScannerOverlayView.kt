package com.secure.qrreader.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.PorterDuff
import android.graphics.PorterDuffXfermode
import android.graphics.RectF
import android.util.AttributeSet
import android.view.View
import androidx.core.content.ContextCompat
import com.secure.qrreader.R

/**
 * Custom view that draws a dark overlay with a transparent scanning window.
 * The window is centered and has rounded corners with accent color indicators.
 */
class ScannerOverlayView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private val overlayPaint = Paint().apply {
        color = 0xE6000000.toInt() // Dark semi-transparent
        style = Paint.Style.FILL
    }

    private val clearPaint = Paint().apply {
        xfermode = PorterDuffXfermode(PorterDuff.Mode.CLEAR)
        isAntiAlias = true
    }

    private val cornerPaint = Paint().apply {
        color = ContextCompat.getColor(context, R.color.primary)
        style = Paint.Style.FILL
        isAntiAlias = true
    }

    private val windowRect = RectF()
    private val cornerLength = 48f
    private val cornerThickness = 4f
    private val cornerRadius = 12f

    // Window size relative to view (70% of view size, min 200dp)
    private var windowSize = 0f
    private val windowSizeRatio = 0.75f
    private val minWindowSize = 200f * context.resources.displayMetrics.density

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        windowSize = maxOf(minWindowSize, minOf(w, h) * windowSizeRatio)
        val centerX = w / 2f
        val centerY = h / 2f
        val halfWindow = windowSize / 2f
        windowRect.set(
            centerX - halfWindow,
            centerY - halfWindow,
            centerX + halfWindow,
            centerY + halfWindow
        )
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        // Save layer to apply clear mode
        val saveCount = canvas.saveLayer(0f, 0f, width.toFloat(), height.toFloat(), null)

        // Draw dark overlay
        canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), overlayPaint)

        // Clear the scanning window area (create the hole)
        canvas.drawRoundRect(windowRect, cornerRadius, cornerRadius, clearPaint)

        // Restore layer
        canvas.restoreToCount(saveCount)

        // Draw corner indicators
        drawCorners(canvas)
    }

    private fun drawCorners(canvas: Canvas) {
        val left = windowRect.left
        val top = windowRect.top
        val right = windowRect.right
        val bottom = windowRect.bottom
        val margin = 16f * context.resources.displayMetrics.density

        // Top-left corners
        canvas.drawRect(left + margin, top + margin, left + margin + cornerLength, top + margin + cornerThickness, cornerPaint)
        canvas.drawRect(left + margin, top + margin, left + margin + cornerThickness, top + margin + cornerLength, cornerPaint)

        // Top-right corners
        canvas.drawRect(right - margin - cornerLength, top + margin, right - margin, top + margin + cornerThickness, cornerPaint)
        canvas.drawRect(right - margin - cornerThickness, top + margin, right - margin, top + margin + cornerLength, cornerPaint)

        // Bottom-left corners
        canvas.drawRect(left + margin, bottom - margin - cornerThickness, left + margin + cornerLength, bottom - margin, cornerPaint)
        canvas.drawRect(left + margin, bottom - margin - cornerLength, left + margin + cornerThickness, bottom - margin, cornerPaint)

        // Bottom-right corners
        canvas.drawRect(right - margin - cornerLength, bottom - margin - cornerThickness, right - margin, bottom - margin, cornerPaint)
        canvas.drawRect(right - margin - cornerThickness, bottom - margin - cornerLength, right - margin, bottom - margin, cornerPaint)
    }
}