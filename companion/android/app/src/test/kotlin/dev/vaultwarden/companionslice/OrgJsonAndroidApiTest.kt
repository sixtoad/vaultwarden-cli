package dev.vaultwarden.companionslice

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.lang.reflect.Modifier

/**
 * The unit tests run against Maven org.json, a superset of Android's org.json
 * (e.g. `JSONObject.keySet()` is `@hide` on Android, so a call compiles here
 * and fails against android.jar). This refuses, in the main sources, every
 * public org.json member that the Maven artifact has and Android's public API
 * (API 30, the minSdk) does not.
 */
class OrgJsonAndroidApiTest {
    /** Android's public `org.json.JSONObject` methods (developer.android.com, API 30). */
    private val androidObject = setOf(
        "accumulate", "get", "getBoolean", "getDouble", "getInt", "getJSONArray", "getJSONObject",
        "getLong", "getString", "has", "isNull", "keys", "length", "names", "numberToString", "opt",
        "optBoolean", "optDouble", "optInt", "optJSONArray", "optJSONObject", "optLong", "optString",
        "put", "putOpt", "quote", "remove", "toJSONArray", "toString", "wrap",
    )

    /** Android's public `org.json.JSONArray` methods (API 30). */
    private val androidArray = setOf(
        "get", "getBoolean", "getDouble", "getInt", "getJSONArray", "getJSONObject", "getLong",
        "getString", "isNull", "join", "length", "opt", "optBoolean", "optDouble", "optInt",
        "optJSONArray", "optJSONObject", "optLong", "optString", "put", "remove", "toJSONObject",
        "toString",
    )

    /**
     * Maven-only names that Kotlin and Java collections, streams and builders
     * also use; scanning for them would refuse ordinary code. A call of one of
     * these on a JSON value is not caught here.
     */
    private val ambiguous = setOf("append", "clear", "equals", "hashCode", "isEmpty", "iterator", "putAll", "toList", "write")

    /** Declared by the class itself: inherited `Iterable`/`Object` members are not org.json's. */
    private fun publicNames(type: Class<*>): Set<String> = type.methods
        .filter { Modifier.isPublic(it.modifiers) && it.declaringClass == type }
        .map { it.name }
        .toSet()

    private val mavenOnly: Set<String> by lazy {
        (publicNames(JSONObject::class.java) - androidObject - ambiguous) +
            (publicNames(JSONArray::class.java) - androidArray - ambiguous)
    }

    @Test fun theScanKnowsTheHiddenMembers() {
        assertTrue("keySet", "keySet" in mavenOnly)
        assertTrue("toMap", "toMap" in mavenOnly)
    }

    @Test fun mainSourcesUseOnlyAndroidPublicOrgJson() {
        val sources = File(Fixtures.root, "companion/android/app/src/main/kotlin")
        val files = sources.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        assertTrue("main sources found under ${sources.path}", files.isNotEmpty())
        val call = Regex("""(?:\.|::)([A-Za-z_][A-Za-z0-9_]*)\s*\(?""")
        val found = files.flatMap { file ->
            file.readLines().withIndex().flatMap { (index, line) ->
                call.findAll(line.substringBefore("//"))
                    .map { it.groupValues[1] }
                    .filter { it in mavenOnly }
                    .map { "${file.name}:${index + 1}: $it" }
                    .toList()
            }
        }
        assertEquals("org.json members that are not public on Android", emptyList<String>(), found)
    }
}
