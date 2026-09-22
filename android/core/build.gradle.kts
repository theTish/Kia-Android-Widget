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
        // Only the watch tile sends this - the phone picks its own climate
        // settings. Empty means the plain default: 21 degrees, heaters off.
        buildConfigField(
            "String",
            "KIA_CLIMATE_PRESET",
            "\"${secret("KIA_CLIMATE_PRESET")}\"",
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

dependencies {
    // ClimateSync: the phone publishes its climate choice, the watch reads it.
    implementation("com.google.android.gms:play-services-wearable:19.0.0")

    // The geofence decides whether to lock a car on its own. Its rules are
    // plain Kotlin precisely so they can be tested without a device.
    testImplementation("junit:junit:4.13.2")
    // Android's org.json is a stub off-device; the real one lets the /status
    // parser be tested against the payloads it is written for.
    testImplementation("org.json:json:20240303")
}
