# Bouncy Castle lightweight API classes are reached reflectively in places.
-keep class org.bouncycastle.crypto.** { *; }
-dontwarn org.bouncycastle.**

# ZXing / journeyapps scanner.
-keep class com.journeyapps.barcodescanner.** { *; }
-keep class com.google.zxing.** { *; }

# Never keep source file names / line numbers out of crash reports for our own
# code, but do not expose anything about key handling paths either.
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable
