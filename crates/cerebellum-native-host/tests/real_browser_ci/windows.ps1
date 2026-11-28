param([switch] $ReleaseTests)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or !$IsWindows) {
    throw 'Run the browser image suite on a disposable GitHub-hosted runner.'
}
$scratch = Join-Path $env:RUNNER_TEMP "ck-real-browser-$([Guid]::NewGuid())"
$null = New-Item -ItemType Directory -Path $scratch
$daemon = $null

function Find-CargoExecutable($Messages, [string] $Name) {
    $executables = @($Messages | ForEach-Object { ConvertFrom-Json $_ } | Where-Object {
        $_.reason -eq 'compiler-artifact' -and $_.target.name -eq $Name -and $_.executable
    } | Select-Object -ExpandProperty executable)
    if ($executables.Count -ne 1) { throw "Expected one executable for $Name." }
    return $executables[0]
}

try {
    $artifacts = cargo build --locked --release -p cerebellum-bridge-protocol --bin peer-trailer --message-format=json
    if ($LASTEXITCODE -ne 0) { throw "Could not build peer-trailer (exit $LASTEXITCODE)." }
    $env:CK_IMAGE_TEST_TRAILER = Find-CargoExecutable $artifacts 'peer-trailer'

    if (!$ReleaseTests) {
    $csc = Join-Path ([Environment]::SystemDirectory) '..\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $env:CK_IMAGE_TEST_WINDOWS_LAUNCHER = Join-Path $scratch 'parent-fixture.exe'
    & $csc /nologo /target:exe "/out:$env:CK_IMAGE_TEST_WINDOWS_LAUNCHER" (Join-Path $PSScriptRoot 'windows-parent.cs')
    if ($LASTEXITCODE -ne 0) { throw "Could not build the Windows parent fixture (exit $LASTEXITCODE)." }

    $env:CK_IMAGE_TEST_WINDOWS_CMD = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
    $chrome = @( ${env:ProgramFiles}, ${env:ProgramFiles(x86)} ) | Where-Object { $_ } | ForEach-Object {
        Join-Path $_ 'Google\Chrome\Application\chrome.exe'
    } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (!$chrome) { throw 'Chrome Stable must be installed machine-wide.' }
    $env:CK_IMAGE_TEST_WINDOWS_CHROME = $chrome

    cargo test --locked --release -p cerebellum-native-host --features bridge-test-identities `
        --test real_browser_ci windows:: -- --ignored --skip windows::fixture_entry --nocapture --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw "Windows browser predicate tests failed (exit $LASTEXITCODE)." }
    return
    }

    cargo test --locked --release -p cerebellum-native-host --features bridge-test-identities `
        --test real_browser_ci --no-run
    if ($LASTEXITCODE -ne 0) { throw "Could not build the release host fixtures (exit $LASTEXITCODE)." }

    $artifacts = cargo test --locked --release -p cerebellum --features bridge-test-identities `
        --test bridge_peer_ci --no-run --message-format=json
    if ($LASTEXITCODE -ne 0) { throw "Could not build the scratch Subc daemon fixture (exit $LASTEXITCODE)." }
    $testExe = Find-CargoExecutable $artifacts 'bridge_peer_ci'
    $server = Find-CargoExecutable $artifacts 'ck-cerebellum'
    $env:CK_BRIDGE_CI_COORD = $scratch
    $env:CK_BRIDGE_CI_SERVER = Join-Path $scratch 'ck-cerebellum.exe'
    Copy-Item -LiteralPath $server -Destination $env:CK_BRIDGE_CI_SERVER
    & $env:CK_IMAGE_TEST_TRAILER sign --test-key $env:CK_BRIDGE_CI_SERVER cerebellum x86_64-pc-windows-msvc ci
    if ($LASTEXITCODE -ne 0) { throw "Could not sign the release daemon fixture (exit $LASTEXITCODE)." }

    $daemonOutput = Join-Path $scratch 'daemon.out'
    $daemonError = Join-Path $scratch 'daemon.err'
    $daemon = Start-Process -FilePath $testExe -ArgumentList '--exact', 'scratch_subc_serves_the_signed_bridge', '--nocapture' `
        -PassThru -NoNewWindow -RedirectStandardOutput $daemonOutput -RedirectStandardError $daemonError
    cargo test --locked --release -p cerebellum-native-host --features bridge-test-identities `
        --test real_browser_ci release_sessions::signed_release -- --ignored --nocapture --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw "Windows signed release process tests failed (exit $LASTEXITCODE)." }
    Write-Host 'Windows signed release process tests exited 0.'
} catch {
    # Print the primary failure before cleanup can raise another exception.
    [Console]::Error.WriteLine("Windows real-browser fixture failed: $_")
    throw
} finally {
    $daemonCode = 0
    $daemonTimedOut = $false
    if ($daemon) {
        $null = New-Item -ItemType File -Path (Join-Path $scratch 'stop') -Force
        if (!$daemon.WaitForExit(35000)) {
            $daemonTimedOut = $true
            [Console]::Error.WriteLine("Scratch Subc daemon PID $($daemon.Id) did not stop within 35 seconds; killing it.")
            $daemon.Kill($true)
            $daemon.WaitForExit()
        }
        $daemonCode = $daemon.ExitCode
        Write-Host "Scratch Subc daemon PID $($daemon.Id) exited $daemonCode."
        $daemon.Dispose()
        Get-Content -LiteralPath $daemonOutput, $daemonError
    }
    Remove-Item -LiteralPath $scratch -Recurse -Force
    if ($daemonTimedOut) { throw 'The scratch Subc daemon timed out during shutdown.' }
    if ($daemonCode -ne 0) { throw "The scratch Subc daemon failed (exit $daemonCode)." }
}
