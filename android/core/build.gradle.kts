// Imported explicitly: inside the Kotlin DSL, a bare `java` resolves to
// Gradle's java extension rather than the java.* package.
import java.util.Properties

plugins {
    id("com.android.library")
}

// The API key lives in local.properties (gitignored) or the environment, never
// in a tracked file. Both the watch tile and the phone app read it from here,
// so it is defined once in this module rather than in each consumer.
val localProps = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

fun secret(key: String, fallback: String = ""): String =
    localProps.getProperty(key) ?: System.getenv(key) ?: fallback

android {
    namespace = "ca.thetish.kia.core"
    compileSdk = 35

    defaultConfig {
        // Lower than either consumer so both can depend on this module.
        minSdk = 26

        buildConfigField(
            "String",
            "KIA_BASE_URL",
            "\"${secret("KIA_BASE_URL", "https://kia-android-widget.vercel.app")}\"",
        )
        buildConfigField("String", "KIA_SECRET", "\"${secret("KIA_SECRET")}\"")
        buildConfigField(
            "String",
            "KIA_CLIMATE_PRESET",
            "\"${secret("KIA_CLIMATE_PRESET", "winter")}\"",
        )
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
