// Imported explicitly: inside the Kotlin DSL, a bare `java` resolves to
// Gradle's java extension rather than the java.* package.
import java.util.Properties

plugins {
    id("com.android.application")
}

// Secrets come from local.properties (gitignored) or the environment.
// Nothing sensitive is ever written into a tracked file.
val localProps = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

fun secret(key: String, fallback: String = ""): String =
    localProps.getProperty(key) ?: System.getenv(key) ?: fallback

android {
    namespace = "ca.thetish.kiatile"
    compileSdk = 35

    defaultConfig {
        applicationId = "ca.thetish.kiatile"
        minSdk = 30
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        buildConfigField(
            "String", "KIA_BASE_URL",
            "\"${secret("KIA_BASE_URL", "https://kia-android-widget.vercel.app")}\""
        )
        buildConfigField("String", "KIA_SECRET", "\"${secret("KIA_SECRET")}\"")
        buildConfigField(
            "String", "KIA_CLIMATE_PRESET",
            "\"${secret("KIA_CLIMATE_PRESET", "winter")}\""
        )
    }

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("androidx.wear.tiles:tiles:1.6.2")
    implementation("androidx.wear.protolayout:protolayout:1.4.2")
    implementation("androidx.wear.protolayout:protolayout-expression:1.4.2")
    implementation("androidx.concurrent:concurrent-futures:1.3.0")
    implementation("androidx.annotation:annotation:1.10.0")
}
