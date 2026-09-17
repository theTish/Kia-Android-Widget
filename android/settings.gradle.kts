pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "kia-android"

// :core holds the API client and the build-time secrets.
// :tile is the Wear OS tile, :app the phone app and its widget.
include(":core")
include(":tile")
include(":app")
