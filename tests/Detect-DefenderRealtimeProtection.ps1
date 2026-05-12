$rtp = Get-MpPreference
if ($rtp.DisableRealtimeMonitoring -eq $false) {
    Write-Output "Compliant: Real-time protection is enabled."
    exit 0
}
else {
    Write-Output "Noncompliant: Real-time protection is disabled."
    exit 1
}