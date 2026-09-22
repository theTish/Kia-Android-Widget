plugins {
    id("com.android.application")
}

android {
    namespace = "ca.thetish.kiatile"
    compileSdk = 35

    defaultConfig {
        // The phone's package name, not its own: the Data Layer only connects
        // apps that match on both ends, and ClimateSync needs it to.
        applicationId = "ca.thetish.kia.app"
        // Wear OS 3.
        minSdk = 30
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

    implementation("androidx.wear.tiles:tiles:1.6.2")
    implementation("androidx.wear.protolayout:protolayout:1.4.2")
    implementation("androidx.wear.protolayout:protolayout-expression:1.4.2")
    implementation("androidx.concurrent:concurrent-futures:1.3.0")
    implementation("androidx.annotation:annotation:1.10.0")
}
