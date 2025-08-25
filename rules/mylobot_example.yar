rule MyloBot_String_Rule {
    meta:
        author = "Muhammad Askari"
        description = "Detects suspect strings related to MyloBot"
        date = "2025-08-21"
    strings:
        $s1 = "MyloBot" nocase
        $s2 = "moli1369" nocase
    condition:
        any of them
}
