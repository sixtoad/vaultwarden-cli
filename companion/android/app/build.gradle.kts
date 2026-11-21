plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Android approval client (#60 phase 1). The application id matches the macOS
// bundle identifier (`companion/macos/Runner/Configs/AppInfo.xcconfig`).
android {
    namespace = "dev.vaultwarden.companionslice"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "dev.vaultwarden.companionSlice"
        // API 30 (Android 11) is the floor: per-operation Keystore
        // authentication (`setUserAuthenticationParameters(0, BIOMETRIC_STRONG)`)
        // and `KeyInfo` authenticator types exist from API 30. Older devices
        // would need the legacy `-1` validity path, which this client refuses.
        minSdk = 30
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        // The Rust core is built for arm64 only (`aarch64-linux-android`).
        ndk { abiFilters += listOf("arm64-v8a") }
    }

    buildTypes {
        release {
            // Release signing is not configured: phase 1 ships no release APK.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    // The CI job copies the bridge library here (gitignored); a debug build
    // without it still builds and reports the core as unavailable.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")

    testOptions {
        unitTests.all {
            // Unit tests read the shared golden transcript fixture.
            it.systemProperty("vw.repoRoot", rootProject.projectDir.resolve("../..").canonicalPath)
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

dependencies {
    // BiometricPrompt with a CryptoObject: the only way a signature is produced.
    implementation("androidx.biometric:biometric:1.1.0")
    testImplementation("junit:junit:4.13.2")
    // android.jar's org.json is a stub in JVM unit tests.
    testImplementation("org.json:json:20240303")
}

flutter {
    source = "../.."
}
