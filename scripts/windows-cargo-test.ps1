[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string[]] $CargoArgs,
    [switch] $Ignored,
    [ValidateRange(1, 600)] [int] $IdleSeconds = 120
)

$ErrorActionPreference = 'Stop'

$start = [System.Diagnostics.ProcessStartInfo]::new()
$start.FileName = (Get-Command cargo -CommandType Application | Select-Object -First 1).Source
$start.WorkingDirectory = (Get-Location).ProviderPath
$start.UseShellExecute = $false
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true

# Serial libtest prints the case name before it starts, even without a newline.
# Keep the pretty result lines so CI can still verify which cases passed.
$arguments = @('test') + $CargoArgs + @('--', '--format=pretty', '--test-threads=1')
if ($Ignored) { $arguments += '--ignored' }
foreach ($argument in $arguments) { $start.ArgumentList.Add($argument) }

$progress = @{
    Armed = $false
    LastTest = '(no case name printed)'
    Clock = [System.Diagnostics.Stopwatch]::new()
}

function Update-TestProgress([string] $Line, [bool] $Complete) {
    if ($Complete -and $Line -cmatch '^running [1-9][0-9]* tests?\s*$') {
        $progress.Armed = $true
        $progress.LastTest = '(no case name printed)'
        $progress.Clock.Restart()
    } elseif ($progress.Armed -and $Line -cmatch '^test (\S+) \.\.\.') {
        if ($Complete -or $progress.LastTest -cne $Matches[1]) {
            $progress.LastTest = $Matches[1]
            $progress.Clock.Restart()
        }
    }
}

$cargo = [System.Diagnostics.Process]::Start($start)
try {
    $streams = @(
        @{ Reader = $cargo.StandardOutput; IsError = $false },
        @{ Reader = $cargo.StandardError; IsError = $true }
    )
    foreach ($stream in $streams) {
        $stream.Buffer = [char[]]::new(4096)
        $stream.Pending = ''
        $stream.Done = $false
        $stream.Read = $stream.Reader.ReadAsync($stream.Buffer, 0, $stream.Buffer.Length)
    }

    while (-not $cargo.HasExited -or ($streams | Where-Object { -not $_.Done })) {
        foreach ($stream in $streams) {
            if ($stream.Done -or -not $stream.Read.IsCompleted) { continue }
            $size = $stream.Read.GetAwaiter().GetResult()
            if ($size -eq 0) {
                $stream.Done = $true
                if ($stream.Pending.Length -ne 0) {
                    if ($stream.IsError) { [Console]::Error.WriteLine($stream.Pending) }
                    else { Write-Output $stream.Pending }
                }
                continue
            }

            $stream.Pending += [string]::new($stream.Buffer, 0, $size)
            $stream.Read = $stream.Reader.ReadAsync($stream.Buffer, 0, $stream.Buffer.Length)
            while (($newline = $stream.Pending.IndexOf("`n")) -ge 0) {
                $line = $stream.Pending.Substring(0, $newline).TrimEnd([char]13)
                $stream.Pending = $stream.Pending.Substring($newline + 1)
                if ($stream.IsError) {
                    [Console]::Error.WriteLine($line)
                } else {
                    Update-TestProgress $line $true
                    Write-Output $line
                }
            }
            if (-not $stream.IsError) { Update-TestProgress $stream.Pending $false }
        }

        if ($progress.Armed -and $progress.Clock.Elapsed.TotalSeconds -ge $IdleSeconds) {
            throw "No libtest progress for $IdleSeconds seconds. Last test started: $($progress.LastTest)"
        }
        Start-Sleep -Milliseconds 100
    }
    exit $cargo.ExitCode
} finally {
    if (-not $cargo.HasExited) {
        & "$env:SystemRoot\System32\taskkill.exe" /PID $cargo.Id /T /F | Out-Host
    }
    $cargo.Dispose()
}
