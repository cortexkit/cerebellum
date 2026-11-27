# Run only under a disposable Windows account, with a gate-open host executable.
param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][switch]$DisposableAccount
)
$ErrorActionPreference = 'Stop'
if (!$DisposableAccount) { throw 'This test requires a disposable Windows account.' }
$key = 'Software\Google\Chrome\NativeMessagingHosts\com.cortexkit.cerebellum'
$regPath = "Registry::HKEY_CURRENT_USER\$key"
if (Test-Path -LiteralPath $regPath) { throw "Refusing to replace an existing Chrome registration: $regPath" }
$scratch = Join-Path ([System.IO.Path]::GetTempPath()) "cknh-register-$([guid]::NewGuid())"
$oldAppData = $env:LOCALAPPDATA
$env:LOCALAPPDATA = $scratch

try {
    # Build servers can alias the Cargo directory with a mapped drive. Run a
    # copy from the disposable directory so both path readings use one drive.
    New-Item -ItemType Directory -Path $scratch | Out-Null
    $hostCopy = Join-Path $scratch 'ck-cerebellum-native-host.exe'
    Copy-Item -LiteralPath $Executable -Destination $hostCopy
    $exe = Get-Item -LiteralPath $hostCopy
    $manifestPath = Join-Path $scratch 'CortexKit\cerebellum\com.cortexkit.cerebellum.json'
    $first = $null
    foreach ($attempt in 1, 2) {
        & $exe.FullName --register
        if ($LASTEXITCODE -ne 0) { throw "--register exited $LASTEXITCODE" }
        $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
        if ($manifest.name -cne 'com.cortexkit.cerebellum' -or
            $manifest.description -cne 'CortexKit Chrome bridge' -or
            $manifest.type -cne 'stdio' -or
            $manifest.allowed_origins.Count -ne 1 -or
            $manifest.allowed_origins[0] -cne 'chrome-extension://bfmlflnlaflnibiellpjjifdbcifciei/') {
            throw 'Unexpected native host manifest contents'
        }
        if ($manifest.path.StartsWith('\\?\') -or (Get-Item -LiteralPath $manifest.path).FullName -ne $exe.FullName) {
            throw "Unexpected host path: $($manifest.path)"
        }
        $registration = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($key)
        if ($null -eq $registration) { throw 'Missing HKCU registration' }
        try {
            if ($registration.GetValueKind('') -ne [Microsoft.Win32.RegistryValueKind]::String -or
                $registration.GetValue('') -cne $manifestPath) { throw 'HKCU default REG_SZ does not point to the manifest' }
        } finally { $registration.Dispose() }
        $hash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
        if ($attempt -eq 1) { $first = $hash }
        elseif ($hash -cne $first) { throw 'Second registration wrote different manifest bytes' }
    }
    Write-Output 'Windows registration: manifest fields, drive path, HKCU default REG_SZ and repeat bytes passed'
} finally {
    $env:LOCALAPPDATA = $oldAppData
    if (Test-Path -LiteralPath $regPath) { Remove-Item -LiteralPath $regPath }
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse }
}
