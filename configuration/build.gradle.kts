import de.gematik.zeta.sdk.buildlogic.isJvmEnabled
import de.gematik.zeta.sdk.buildlogic.isNativeEnabled
import de.gematik.zeta.sdk.buildlogic.setupBuildLogic
import org.jetbrains.kotlin.gradle.dsl.ExplicitApiMode

plugins {
    id("de.gematik.zeta.sdk.build-logic.kmp")
    id("de.gematik.zeta.sdk.build-logic.publish")
    id("de.gematik.zeta.sdk.build-logic.sharedlib")
    id("org.jetbrains.kotlin.plugin.serialization")
}

setupBuildLogic {

    kotlin {
        explicitApi = ExplicitApiMode.Disabled

        sourceSets.commonMain.dependencies {
            implementation(project(":network"))
            implementation(project(":storage"))
            implementation(libs.json.schema.validator)
        }

        sourceSets.commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.coroutines.test)
            implementation(libs.ktor.client.mock)
        }

        if (project.isJvmEnabled) {
            sourceSets.jvmTest.dependencies {
                implementation(kotlin("test"))
            }
        }

        if (project.isNativeEnabled) {
            sourceSets.getByName("desktopMain").dependencies {
                implementation(libs.okio)
            }
        }
    }

}
