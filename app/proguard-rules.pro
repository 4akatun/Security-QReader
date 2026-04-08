# Add project specific ProGuard rules here.
# Security: Obfuscation rules for QR Reader

# Keep ML Kit classes
-keep class com.google.mlkit.** { *; }
-dontwarn com.google.mlkit.**

# Keep CameraX classes
-keep class androidx.camera.** { *; }
-dontwarn androidx.camera.**

# Keep Kotlin serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

-keepclassmembers class kotlinx.serialization.json.** {
    *** Companion;
}
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Keep data classes used for serialization
-keep class com.secure.qrreader.model.** { *; }

# Security: Remove all logging in release builds
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}

# Security: Obfuscate class names
-repackageclasses ''
-allowaccessmodification

# Security: Enable optimizations (removing these would reduce security)
# -dontoptimize and -dontpreverify are removed for better R8 optimization

# Security: Remove debug info
-keepattributes SourceFile,LineNumberTable
-keepattributes *Annotation*

# Keep Conscrypt classes
-keep class org.conscrypt.** { *; }
-dontwarn org.conscrypt.**

# Keep Android platform classes referenced by Conscrypt
-keep class org.apache.harmony.xnet.provider.jsse.** { *; }
-dontwarn org.apache.harmony.xnet.provider.jsse.**

# Keep R class
-keep class com.secure.qrreader.R { *; }
-keepclassmembers class com.secure.qrreader.R$* {
    public static <fields>;
}
