# Add project specific ProGuard rules here.
-keepattributes *Annotation*
-keep class com.securityscanner.app.** { *; }
-keep class sun.security.x509.** { *; }
-keep class sun.security.util.** { *; }
-dontwarn sun.security.**
