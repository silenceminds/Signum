param(
    [string]$AgentExe = "$PSScriptRoot\..\signum-agent\build\signum-agent.exe",
    [string]$EdgeIp = "127.0.0.1",
    [int]$ControlPort = 4443
)

$resolved = (Resolve-Path $AgentExe -ErrorAction SilentlyContinue)
$prog = if ($resolved) { $resolved.Path } else { $AgentExe }

Write-Output "[signum-fw] Applying Windows Defender Firewall rules for $prog (Edge=${EdgeIp}:${ControlPort})..."

# Remove stale rules if present
Remove-NetFirewallRule -DisplayName "Signum-Agent-Block-Inbound" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "Signum-Agent-Allow-Edge-Outbound" -ErrorAction SilentlyContinue

# Block ALL inbound connections to signum-agent.exe
New-NetFirewallRule -DisplayName "Signum-Agent-Block-Inbound" `
    -Direction Inbound -Program $prog -Action Block -Profile Any | Out-Null

# Allow outbound ONLY to the configured Edge IP and control port (:4443)
New-NetFirewallRule -DisplayName "Signum-Agent-Allow-Edge-Outbound" `
    -Direction Outbound -Program $prog -Protocol TCP -RemoteAddress $EdgeIp -RemotePort $ControlPort `
    -Action Allow -Profile Any | Out-Null

Write-Output "[signum-fw] Windows agent firewall rules configured."
