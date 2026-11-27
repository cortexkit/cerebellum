$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or !$IsWindows) {
    throw 'This test installs an ephemeral root and runs only on GitHub-hosted Windows runners.'
}

function Invoke-PredicateTest([string] $Filter, [bool] $Ignored, [string] $Package = 'cerebellum-bridge-protocol') {
    $start = [System.Diagnostics.ProcessStartInfo]::new('cargo')
    $start.UseShellExecute = $false
    $arguments = @('test', '--release', '--locked', '-p', $Package, '--lib', $Filter, '--')
    if ($Ignored) { $arguments += '--ignored' }
    foreach ($arg in $arguments) { $start.ArgumentList.Add($arg) }
    $process = [System.Diagnostics.Process]::Start($start)
    try {
        if (!$process.WaitForExit(150000)) {
            $process.Kill($true)
            throw "Windows image predicate test timed out: $Filter"
        }
        if ($process.ExitCode -ne 0) { throw "Windows image predicate test failed: $Filter" }
    } finally {
        $process.Dispose()
    }
}

if ((Get-Service CryptSvc).Status -ne 'Running') {
    throw 'The Windows Cryptographic Services catalog service must be running.'
}
Invoke-PredicateTest 'browser_image::' $false 'cerebellum-windows'
Invoke-PredicateTest 'windows::tests' $false
Invoke-PredicateTest 'native_system_and_chrome_signers_are_isolated' $true

$scratch = Join-Path $env:RUNNER_TEMP "ck-image-predicates-$([Guid]::NewGuid())"
$root = $null
$leaf = $null
try {
    $null = New-Item -ItemType Directory -Path $scratch
    $source = Join-Path $scratch 'fixture.cs'
    $image = Join-Path $scratch 'fixture.exe'
    $publicRoot = Join-Path $scratch 'root.cer'
    Set-Content -Encoding ASCII -Path $source -Value @'
using System.Reflection;
[assembly: AssemblyProduct("Google Chrome")]
internal static class Fixture { private static void Main() {} }
'@
    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $csc /nologo /target:exe "/out:$image" $source
    if ($LASTEXITCODE -ne 0) { throw 'Could not compile the signer-isolation fixture.' }

    $root = New-SelfSignedCertificate -Type Custom -Subject "CN=CK disposable test root $([Guid]::NewGuid())" `
        -KeyUsage CertSign, CRLSign -TextExtension '2.5.29.19={critical}{text}CA=TRUE' `
        -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(2)
    $leaf = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Google LLC, O=Google LLC' `
        -Signer $root -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    $signature = Set-AuthenticodeSignature -LiteralPath $image -Certificate $leaf -IncludeChain All -HashAlgorithm SHA256
    if ($signature.SignerCertificate.Thumbprint -ne $leaf.Thumbprint) { throw 'Fixture not signed by the test leaf.' }

    $storePath = "Cert:\LocalMachine\Root\$($root.Thumbprint)"
    if ((Test-Path -LiteralPath $storePath) -or (Test-Path -LiteralPath "Cert:\CurrentUser\Root\$($root.Thumbprint)")) {
        throw 'The fresh root is already in a trust store.'
    }
    $env:CK_TEST_SIGNED_PE = $image
    $env:CK_TEST_SIGNED_PE_TRUSTED = '0'
    Invoke-PredicateTest 'native_fixture_chain' $true

    $null = Export-Certificate -Cert $root -FilePath $publicRoot
    $null = Import-Certificate -FilePath $publicRoot -CertStoreLocation Cert:\LocalMachine\Root
    $env:CK_TEST_SIGNED_PE_TRUSTED = '1'
    Invoke-PredicateTest 'native_fixture_chain' $true
} finally {
    $cleanupErrors = @()
    foreach ($cert in @($leaf, $root)) {
        if (!$cert) { continue }
        $personal = "Cert:\CurrentUser\My\$($cert.Thumbprint)"
        $machine = "Cert:\LocalMachine\Root\$($cert.Thumbprint)"
        if (Test-Path -LiteralPath $machine) {
            Remove-Item -LiteralPath $machine -ErrorAction Continue -ErrorVariable +cleanupErrors
        }
        if (Test-Path -LiteralPath $personal) {
            Remove-Item -LiteralPath $personal -DeleteKey -ErrorAction Continue -ErrorVariable +cleanupErrors
        }
        foreach ($path in @($personal, $machine, "Cert:\CurrentUser\Root\$($cert.Thumbprint)")) {
            if (Test-Path -LiteralPath $path) { $cleanupErrors += "Certificate remains at $path" }
        }
    }
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
    if ($cleanupErrors.Count) { throw "Failed to remove ephemeral test certificates: $cleanupErrors" }
}

# Find a real Google-signed executable with a different declared product. The
# Rust predicate independently verifies the signer and reads the signed PE.
$google = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | ForEach-Object { Join-Path $_ 'Google' } | Select-Object -Unique
$products = @($google | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object {
    Get-ChildItem -LiteralPath $_ -Recurse -File -Filter '*.exe' | Where-Object {
        $_.VersionInfo.ProductName -and $_.VersionInfo.ProductName -cne 'Google Chrome'
    }
})
if ($products.Count -eq 0) { throw 'No installed Google non-Chrome product is available for signer isolation.' }
$env:CK_TEST_GOOGLE_PRODUCTS = $products.FullName -join [IO.Path]::PathSeparator
$env:CK_TEST_GOOGLE_PRODUCT_NAMES = ($products | ForEach-Object { $_.VersionInfo.ProductName }) -join "`n"
Invoke-PredicateTest 'native_google_signer_does_not_override_product_name' $true
