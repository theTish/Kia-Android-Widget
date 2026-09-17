plugins {
    id("com.android.application")
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

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    // The API client and the build-time secrets live here.
    implementation(project(":core"))
}
