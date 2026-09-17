// AGP 9 ships Kotlin support built in, so no separate kotlin-android plugin.
// The Compose compiler is still a separate plugin though, and its version has
// to match the Kotlin that AGP bundles - 2.4.20 for AGP 9.4.0.
plugins {
    id("com.android.application") version "9.4.0" apply false
    id("com.android.library") version "9.4.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20" apply false
}
