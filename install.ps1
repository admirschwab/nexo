# Installs or updates Nexo on Windows.
#
#   irm https://raw.githubusercontent.com/admirschwab/nexo/main/install.ps1 | iex
#
# - Downloads nexo.exe from the latest GitHub release and verifies its SHA-256 checksum
# - Installs it to %LOCALAPPDATA%\Programs\nexo (no administrator rights needed)
# - Adds that folder to your user PATH
#
# Running it again updates Nexo to the latest version. Your identity is not touched.

function Install-Nexo {
    $ErrorActionPreference = 'Stop'
    # Makes downloads much faster in Windows PowerShell 5.1
    $ProgressPreference = 'SilentlyContinue'

    $baseUrl = 'https://github.com/admirschwab/nexo/releases/latest/download'
    $asset = 'nexo-windows-x86_64.exe'
    $installDir = Join-Path $env:LOCALAPPDATA 'Programs\nexo'
    $target = Join-Path $installDir 'nexo.exe'

    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'Nexo needs 64-bit Windows.'
    }

    # GitHub requires TLS 1.2, which older Windows PowerShell versions don't enable by default
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $tempDir = Join-Path ([IO.Path]::GetTempPath()) ('nexo-install-' + [Guid]::NewGuid())
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    try {
        $exe = Join-Path $tempDir $asset
        $checksumFile = "$exe.sha256"

        Write-Host 'Downloading Nexo ...'
        Invoke-WebRequest -Uri "$baseUrl/$asset" -OutFile $exe -UseBasicParsing
        Invoke-WebRequest -Uri "$baseUrl/$asset.sha256" -OutFile $checksumFile -UseBasicParsing

        # Checksum file format: "<sha256>  <file name>" (sha256sum may prefix the hash with "\")
        $expected = ((Get-Content -Path $checksumFile -Raw).Trim() -split '\s+')[0].TrimStart('\').ToLower()
        $actual = (Get-FileHash -Path $exe -Algorithm SHA256).Hash.ToLower()

        if ($expected -notmatch '^[0-9a-f]{64}$' -or $actual -ne $expected) {
            throw 'Checksum mismatch: the download is damaged or was modified. Nothing was installed.'
        }

        New-Item -ItemType Directory -Force -Path $installDir | Out-Null

        try {
            Copy-Item -Path $exe -Destination $target -Force
        }
        catch {
            throw "Could not write $target. If Nexo is running, close it and try again."
        }
    }
    finally {
        Remove-Item -Recurse -Force -Path $tempDir -ErrorAction SilentlyContinue
    }

    Add-NexoToPath $installDir

    $version = & $target --version

    Write-Host ''
    Write-Host "Installed $version to $installDir"
    Write-Host 'Run "nexo register" to create an identity, or "nexo login" if you already have one.'
    Write-Host 'Tip: use Windows Terminal, the old console window cannot show emojis.'
}

function Add-NexoToPath([string] $directory) {
    # Read and write the registry directly: [Environment]::SetEnvironmentVariable would
    # store PATH as a plain string and break entries like %USERPROFILE%\...
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)

    try {
        $path = [string] $key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')

        $present = $path -split ';' | Where-Object {
            $_ -ne '' -and [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -eq $directory.TrimEnd('\')
        }

        if (-not $present) {
            # Only append, leave the existing entries exactly as they are. A trailing ";"
            # is kept, so uninstall.ps1 can restore the original value exactly.
            $newPath = if ($path -eq '') {
                $directory
            }
            elseif ($path.EndsWith(';')) {
                "$path$directory;"
            }
            else {
                "$path;$directory"
            }

            $key.SetValue('Path', $newPath, 'ExpandString')
            Send-EnvironmentChanged
        }
    }
    finally {
        $key.Close()
    }

    # Also make `nexo` work in the current terminal right away
    if (($env:Path -split ';') -notcontains $directory) {
        $env:Path = "$env:Path;$directory"
    }
}

# Tells Windows that environment variables changed, so new terminals see the new PATH.
# Setting (and removing) a dummy variable through .NET sends that notification.
function Send-EnvironmentChanged {
    [Environment]::SetEnvironmentVariable('NEXO_INSTALLER', '1', 'User')
    [Environment]::SetEnvironmentVariable('NEXO_INSTALLER', $null, 'User')
}

Install-Nexo
