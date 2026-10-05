# Uninstalls Nexo from Windows.
#
#   irm https://raw.githubusercontent.com/admirschwab/nexo/main/uninstall.ps1 | iex
#
# Removes nexo.exe and its PATH entry. Your identity (%LOCALAPPDATA%\nexo) is kept:
# deleting it without `nexo unregister` would leave your account on the server behind.

function Uninstall-Nexo {
    $ErrorActionPreference = 'Stop'

    $installDir = Join-Path $env:LOCALAPPDATA 'Programs\nexo'
    $target = Join-Path $installDir 'nexo.exe'
    $dataDir = Join-Path $env:LOCALAPPDATA 'nexo'

    if (Test-Path -Path $target) {
        try {
            Remove-Item -Path $target -Force
        }
        catch {
            throw "Could not delete $target. If Nexo is running, close it and try again."
        }
    }

    if ((Test-Path -Path $installDir) -and -not (Get-ChildItem -Path $installDir -Force)) {
        Remove-Item -Path $installDir -Force
    }

    Remove-NexoFromPath $installDir

    Write-Host 'Nexo was uninstalled.'

    if (Test-Path -Path (Join-Path $dataDir 'identity.nexo')) {
        Write-Host ''
        Write-Host "Your identity is still stored in $dataDir"
        Write-Host 'Your account on the server still exists. To delete it completely, install Nexo'
        Write-Host 'again, run "nexo unregister" (this also deletes the identity), then uninstall.'
    }
}

function Remove-NexoFromPath([string] $directory) {
    # Read and write the registry directly to keep entries like %USERPROFILE%\... intact
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)

    try {
        $path = [string] $key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')

        # Empty entries are kept (e.g. a trailing ";"), only the Nexo entry is removed,
        # so everything else stays exactly as it was
        $entries = @($path -split ';')

        $remaining = @($entries | Where-Object {
            $_ -eq '' -or [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -ne $directory.TrimEnd('\')
        })

        if ($remaining.Count -ne $entries.Count) {
            $key.SetValue('Path', ($remaining -join ';'), 'ExpandString')

            # Tell Windows that environment variables changed (see install.ps1)
            [Environment]::SetEnvironmentVariable('NEXO_INSTALLER', '1', 'User')
            [Environment]::SetEnvironmentVariable('NEXO_INSTALLER', $null, 'User')
        }
    }
    finally {
        $key.Close()
    }

    $env:Path = (($env:Path -split ';') | Where-Object { $_ -and $_.TrimEnd('\') -ne $directory.TrimEnd('\') }) -join ';'
}

Uninstall-Nexo
