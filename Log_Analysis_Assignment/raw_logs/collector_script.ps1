
        try {
            $psHistory = Get-Content (Join-Path $env:USERPROFILE "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt") -ErrorAction SilentlyContinue
            if ($psHistory) { $psHistory | Out-File (Join-Path $targetRoot "powershell_history.txt") -Encoding UTF8 }
        } catch {}
        # Save a copy of this collector script for provenance
        $scriptPath = Join-Path $targetRoot "collector_script.ps1"
        $MyInvocation.MyCommand.Definition | Out-File -FilePath $scriptPath -Encoding UTF8
    
