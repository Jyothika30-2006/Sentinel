/* Demo YARA rules for the Sentinel sandbox.
 *
 * These are illustrative signatures — replace with real rules (e.g. from
 * YARA-Forge, MalwareBazaar, or your own threat intel) for production use.
 * They are matched by overlay/forensic_tool.py's `yara` tool inside the
 * network-isolated sandbox.
 */

rule Suspicious_Command_Strings
{
    meta:
        description = "Flags files containing common download/exec command strings"
        author = "Sentinel"
    strings:
        $pwsh = "powershell" nocase
        $cmd  = "cmd.exe" nocase
        $wget = "wget " nocase
        $curl = "curl " nocase
        $b64  = "base64 -d" nocase
    condition:
        2 of them
}

rule Embedded_Executable_Marker
{
    meta:
        description = "Flags files containing embedded PE/DOS executable markers"
        author = "Sentinel"
    strings:
        $mz = "MZ"
        $pe = "This program cannot be run in DOS mode"
    condition:
        $mz and $pe
}
