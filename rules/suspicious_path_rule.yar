rule Suspicious_AppData_Path {
    meta:
        author = "Muhammad Askari"
        description = "Detects executables running from AppData or Temp folders"
    strings:
        $path_appdata = /AppData\\Roaming\\/ nocase
        $path_temp    = /Temp\\/ nocase
    condition:
        $path_appdata or $path_temp
}
