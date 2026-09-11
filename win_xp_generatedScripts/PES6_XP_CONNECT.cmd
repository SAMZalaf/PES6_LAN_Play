@if (@X)==(@Y) @end /*
@echo off
setlocal DisableDelayedExpansion
cscript.exe //nologo //E:JScript "%~f0" "%~1"
set "PES6_RC=%ERRORLEVEL%"
echo.
pause
exit /b %PES6_RC%
*/
var IP = "192.168.1.2", PORT = 5739;
var NAMES = ["pes6gate-ec.winning-eleven.net","pes6online.got-game.org","we9stun.winning-eleven.net","stun6server.got-game.org"];
var BEGIN = "# PES6-LAN BEGIN", END = "# PES6-LAN END";
var fso = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");
var undo = WScript.Arguments.length > 0 && WScript.Arguments(0) == "--undo";
var root = shell.ExpandEnvironmentStrings("%SystemRoot%");
var hosts = root + "\\System32\\drivers\\etc\\hosts";
var backup = hosts + ".pes6_lan.bak";
function named(s) {
    for (var i = 0; i < NAMES.length; i++) if (s.toLowerCase() == NAMES[i]) return true;
    return false;
}
function trim(s) { return s.replace(/^\s+|\s+$/g, ""); }
function read(p) {
    if (!fso.FileExists(p)) return "";
    var h = fso.OpenTextFile(p, 1, false, 0), s = h.ReadAll(); h.Close(); return s;
}
function write(p, s) {
    var h = fso.CreateTextFile(p, true, false); h.Write(s); h.Close();
}
function clean(s) {
    var ls = s.split(/\r?\n/), result = [];
    for (var i = 0; i < ls.length; i++) {
        var line = ls[i];
        if (trim(line) == BEGIN || trim(line) == END) continue;
        var hash = line.indexOf("#"), body = hash < 0 ? line : line.substring(0, hash);
        var comment = hash < 0 ? "" : line.substring(hash);
        var parts = trim(body).split(/\s+/), keep = [], hit = false;
        for (var j = 1; j < parts.length; j++) {
            if (named(parts[j])) hit = true; else keep.push(parts[j]);
        }
        if (hit) {
            if (keep.length) result.push(parts[0] + " " + keep.join(" ") + (comment ? " " + comment : ""));
            else if (comment) result.push(comment);
        } else result.push(line);
    }
    return result.join("\r\n").replace(/[\r\n]+$/, "") + "\r\n";
}
function originals(s) {
    var ls = s.split(/\r?\n/), result = [];
    for (var i = 0; i < ls.length; i++) {
        var parts = trim(ls[i].split("#")[0]).split(/\s+/), keep = [];
        for (var j = 1; j < parts.length; j++) if (named(parts[j])) keep.push(parts[j]);
        if (keep.length) result.push(parts[0] + " " + keep.join(" "));
    }
    return result.length ? result.join("\r\n") + "\r\n" : "";
}
function run(s) { return shell.Run(s, 0, true); }
function firewall() {
    var profiles = [["STANDARD", "StandardProfile"], ["DOMAIN", "DomainProfile"]];
    var title = "PES6 LAN UDP " + PORT;
    var base = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\";
    for (var i = 0; i < profiles.length; i++) {
        var key = base + profiles[i][1] + "\\GloballyOpenPorts\\List\\" + PORT + ":UDP";
        var value = null;
        try { value = String(shell.RegRead(key)); } catch (e) {}
        var ours = value !== null && value.substring(value.length - title.length) == title;
        if (undo) {
            if (ours) run("netsh firewall delete portopening protocol=UDP port=" + PORT + " profile=" + profiles[i][0]);
        } else if (value === null || ours) {
            var rc = run('netsh firewall add portopening protocol=UDP port=' + PORT +
                ' name="' + title + '" mode=ENABLE scope=SUBNET profile=' + profiles[i][0]);
            if (rc) WScript.Echo("WARNING: firewall rule failed. XP SP2/SP3 is required for this command.");
        } else {
            WScript.Echo("Existing UDP " + PORT + " firewall entry kept (" + profiles[i][0] + ").");
        }
    }
}
try {
    WScript.Echo("PES6 LAN - Windows XP setup. Run with an Administrator account.");
    var current = read(hosts);
    if (undo) {
        if (fso.FileExists(backup)) {
            write(hosts, clean(current) + originals(read(backup)));
            fso.DeleteFile(backup, true);
            WScript.Echo("Old game mappings restored. Other current hosts entries retained.");
        } else WScript.Echo("No backup found. Hosts left unchanged.");
    } else {
        if (!fso.FileExists(backup)) write(backup, current);
        var updated = clean(current) + BEGIN + "\r\n";
        for (var i = 0; i < NAMES.length; i++) updated += IP + " " + NAMES[i] + "\r\n";
        write(hosts, updated + END + "\r\n");
        WScript.Echo("Game gateway and STUN now point to " + IP);
        WScript.Echo("Hosts backup: " + backup);
    }
    firewall();
    run("ipconfig /flushdns");
    if (!undo) {
        WScript.Echo("DONE. Restart PES6 if it was open. Game UDP port: " + PORT + "; UPnP: OFF.");
        WScript.Echo("Network -> any non-empty password -> Player profile -> PES6 LAN -> LAN.");
        WScript.Echo("No Python or other software is needed on this PC.");
        WScript.Echo("To undo later: PES6_XP_CONNECT.cmd --undo");
    }
} catch (e) {
    WScript.Echo("SETUP FAILED: " + e.message);
    WScript.Echo("Use an Administrator account. Do not disable the firewall or antivirus.");
    WScript.Echo("If hosts changed before this error, undo with: PES6_XP_CONNECT.cmd --undo");
    WScript.Quit(1);
}
