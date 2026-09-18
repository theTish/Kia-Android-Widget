plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "ca.thetish.kia.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "ca.thetish.kia.app"
        // Android 8.0. Older than the tile because a phone app has no reason
        // to require Wear OS 3's baseline.
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    // The API client and the build-time secrets live here.
    implementation(project(":core"))

    implementation("androidx.glance:glance-appwidget:1.2.0")

    // Widget taps run here, not in the Glance ActionCallback: a
    // BroadcastReceiver is cut off long before a cold car answers.
    implementation("androidx.work:work-runtime-ktx:2.11.2")

    // The geofence. Play Services rather than a foreground service holding GPS
    // all day: it wakes us on the way out of the ring and sleeps otherwise.
    implementation("com.google.android.gms:play-services-location:21.3.0")
    implementation("androidx.core:core-ktx:1.15.0")
}
