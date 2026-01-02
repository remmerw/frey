
plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)
}

group = "io.github.remmerw"
version = "0.2.1"

kotlin {

    androidLibrary {
        namespace = "io.github.remmerw.frey"
        compileSdk = 36
        minSdk = 27



        // Opt-in to enable and configure device-side (instrumented) tests
        withDeviceTest {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
            execution = "ANDROIDX_TEST_ORCHESTRATOR"
        }
    }


    jvm()
    // iosX64()
    // iosArm64()
    // iosSimulatorArm64()
    // linuxArm64()
    // linuxX64()
    // linuxArm64()
    // wasmJs()
    // wasmWasi()
    // js()

    sourceSets {
        commonMain {
            dependencies {
                implementation(libs.kotlin.stdlib)
                implementation(libs.kotlinx.io.core)
            }
        }

        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }
    }
}




mavenPublishing {
    publishToMavenCentral()

    signAllPublications()

    coordinates(group.toString(), "frey", version.toString())

    pom {
        name = "frey"
        description = "DnsResolver client library"
        inceptionYear = "2025"
        url = "https://github.com/remmerw/frey/"
        licenses {
            license {
                name = "The Apache License, Version 2.0"
                url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                distribution = "https://www.apache.org/licenses/LICENSE-2.0.txt"
            }
        }
        developers {
            developer {
                id = "remmerw"
                name = "Remmer Wilts"
                url = "https://github.com/remmerw/"
            }
        }
        scm {
            url = "https://github.com/remmerw/frey/"
            connection = "scm:git:git://github.com/remmerw/frey.git"
            developerConnection = "scm:git:ssh://git@github.com/remmerw/frey.git"
        }
    }
}
