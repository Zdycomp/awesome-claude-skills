plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.zdycomp.secureterm"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.zdycomp.secureterm"
        // minSdk 26: guarantees bionic openpty/forkpty (API 23+) and Keystore AES/GCM.
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        externalNativeBuild {
            cmake {
                // Harden the native library: stack protector, FORTIFY, RELRO/BIND_NOW, no lazy binding.
                cFlags += listOf(
                    "-Wall", "-Wextra", "-Werror",
                    "-fstack-protector-strong",
                    "-D_FORTIFY_SOURCE=2", "-O2"
                )
                arguments += "-DANDROID_ARM_NEON=ON"
            }
        }
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-ktx:1.9.3")
    implementation("androidx.documentfile:documentfile:1.0.1")
}
