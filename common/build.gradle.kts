import de.gematik.zeta.sdk.buildlogic.isAndroidEnabled
import de.gematik.zeta.sdk.buildlogic.setupBuildLogic

plugins {
    id("de.gematik.zeta.sdk.build-logic.kmp")
    id("de.gematik.zeta.sdk.build-logic.publish")
    id("de.gematik.zeta.sdk.build-logic.sharedlib")
    id("org.jetbrains.kotlin.plugin.serialization")
}

setupBuildLogic {
    kotlin {
        tasks.withType<Test> {
            failOnNoDiscoveredTests = false
        }
        sourceSets.commonMain.dependencies {
            api(libs.coroutines.core)
            api(libs.reactivestate.core)
            api(libs.serialization.core)
            api(libs.serialization.json)
        }

        sourceSets.commonTest.dependencies {
            api(kotlin("test"))
            api(libs.coroutines.test)
        }

        if (project.isAndroidEnabled) {
            sourceSets.androidMain.dependencies {
                api(libs.androidx.startup)
            }
        }

        tasks.withType<Test> {
            failOnNoDiscoveredTests = false
        }
    }
}
