import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    `maven-publish`
}

android {
    namespace = "com.tungsten.verifiedpluginload"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        create("fordebug") {
            initWith(getByName("debug"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(libs.gson)
    implementation(libs.bcprov)
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])

                groupId = project.findProperty("GROUP") as String? ?: "com.github.ZalithLauncher"
                artifactId = project.findProperty("POM_ARTIFACT_ID") as String? ?: rootProject.name
                version = project.findProperty("VERSION_NAME") as String? ?: "unspecified"

                pom {
                    name.set(project.findProperty("POM_NAME") as String? ?: rootProject.name)
                    description.set(project.findProperty("POM_DESCRIPTION") as String? ?: "")
                    url.set(project.findProperty("POM_URL") as String? ?: "")

                    licenses {
                        license {
                            name.set(project.findProperty("POM_LICENCE_NAME") as String? ?: "")
                            url.set(project.findProperty("POM_LICENCE_URL") as String? ?: "")
                        }
                    }

                    developers {
                        developer {
                            id.set("BZLZHH")
                            name.set("BZLZHH")
                        }
                    }

                    scm {
                        url.set(project.findProperty("POM_SCM_URL") as String? ?: "")
                        connection.set(project.findProperty("POM_SCM_CONNECTION") as String? ?: "")
                        developerConnection.set(project.findProperty("POM_SCM_DEV_CONNECTION") as String? ?: "")
                    }
                }
            }
        }
    }
}
