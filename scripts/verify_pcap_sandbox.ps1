[CmdletBinding()]
param(
    [string]$DockerExecutable
)

$ErrorActionPreference = 'Stop'
$image = 'token-security-pcap-preflight:local'
$runId = [Guid]::NewGuid().ToString('N')
$runLabel = 'token-security-run=' + $runId
$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$tempRoot = [System.IO.Path]::Combine($tempBase, 'pcap-sandbox-verification-' + $runId)
$containerName = 'pcap-sandbox-probe-' + $runId
$script:FailureCode = 'unexpected_failure'
$residualContainers = 0
$verificationPassed = $false
$containerCleanupRequired = $false

function Fail-Verification {
    param([Parameter(Mandatory = $true)][string]$Code)
    $script:FailureCode = $Code
    throw [System.InvalidOperationException]::new($Code)
}

function Resolve-Docker {
    param([string]$Override)

    if (-not [string]::IsNullOrWhiteSpace($Override)) {
        if (Test-Path -LiteralPath $Override -PathType Leaf) {
            return [System.IO.Path]::GetFullPath($Override)
        }
        Fail-Verification 'docker_unavailable'
    }

    $command = Get-Command docker -ErrorAction SilentlyContinue
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace($command.Source)) {
        return $command.Source
    }

    foreach ($candidate in @(
        [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Programs\DockerDesktop\resources\bin\docker.exe'),
        [System.IO.Path]::Combine($env:ProgramFiles, 'Docker\Docker\resources\bin\docker.exe')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    Fail-Verification 'docker_unavailable'
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Code
    )
    if (-not $Condition) { Fail-Verification $Code }
}

function Get-PropertyNames {
    param([Parameter(Mandatory = $true)]$Value)
    return @($Value.PSObject.Properties | ForEach-Object { $_.Name })
}

function Test-ExactKeys {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )
    $actual = Get-PropertyNames $Value
    if ($actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) {
        if ($actual -notcontains $name) { return $false }
    }
    return $true
}

function Invoke-QuietNative {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$ErrorPath
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $Action 2> $ErrorPath)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = $output }
}

try {
    $docker = Resolve-Docker $DockerExecutable
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $pythonCommand) { Fail-Verification 'python_unavailable' }

    $repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $generator = Join-Path $PSScriptRoot 'new_safe_pcap_fixture.py'
    $launcher = Join-Path $PSScriptRoot 'inspect_pcap.ps1'
    $quarantineRoot = Join-Path $tempRoot 'quarantine'
    $inputDirectory = Join-Path $quarantineRoot 'input'
    $fixture = Join-Path $inputDirectory ('safe-' + $runId + '.pcap')
    $nativeError = Join-Path $tempRoot 'native-command.err'

    New-Item -ItemType Directory -Path $inputDirectory -Force | Out-Null
    $nativeResult = Invoke-QuietNative { & $pythonCommand.Source $generator --output $fixture } $nativeError
    if ($nativeResult.ExitCode -ne 0) { Fail-Verification 'fixture_generation_failed' }

    $nativeResult = Invoke-QuietNative { & $docker build --quiet -f (Join-Path $repositoryRoot 'pcap-inspector\Dockerfile') -t $image $repositoryRoot } $nativeError
    if ($nativeResult.ExitCode -ne 0) { Fail-Verification 'image_build_failed' }

    $nativeResult = Invoke-QuietNative { & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $launcher -Path $fixture -QuarantineRoot $quarantineRoot -DockerExecutable $docker } $nativeError
    if ($nativeResult.ExitCode -ne 0) { Fail-Verification 'launcher_failed' }
    $launcherOutput = $nativeResult.Output

    $reports = @(Get-ChildItem -LiteralPath (Join-Path $quarantineRoot 'output') -Filter 'pcap-preflight-*.json' -File)
    Assert-True ($reports.Count -eq 1) 'report_count_invalid'
    $report = [System.IO.File]::ReadAllText($reports[0].FullName) | ConvertFrom-Json
    Assert-True ($report.capability -eq 'token_eligible') 'report_capability_invalid'
    Assert-True ($report.reasons.Count -eq 1 -and $report.reasons[0] -eq 'plaintext_application_protocol_observed') 'report_reason_invalid'
    Assert-True ($report.protocol_counts.http -gt 0) 'http_not_observed'
    Assert-True ((Get-PropertyNames $report) -notcontains 'payload') 'report_payload_leak'

    $probeCommand = @'
uid=$(id -u)
capeff=$(awk '/^CapEff:/ {print $2}' /proc/self/status)
if sh -c ': > /probe-write' 2>/dev/null; then root_write=1; else root_write=0; fi
if sh -c ': >> /input/capture' 2>/dev/null; then input_write=1; else input_write=0; fi
memory_max=$(cat /sys/fs/cgroup/memory.max)
pids_max=$(cat /sys/fs/cgroup/pids.max)
read cpu_quota cpu_period < /sys/fs/cgroup/cpu.max
printf 'uid=%s\n' $uid
printf 'cap_eff=%s\n' $capeff
printf 'root_write=%s\n' $root_write
printf 'input_write=%s\n' $input_write
printf 'memory_max=%s\n' $memory_max
printf 'pids_max=%s\n' $pids_max
printf 'cpu_max=%s_%s\n' $cpu_quota $cpu_period
'@
    $probeCommand = $probeCommand -replace "`r`n", "`n"

    $createArguments = @(
        'create', '--rm',
        '--name', $containerName,
        '--label', 'token-security-purpose=pcap-sandbox-verification',
        '--label', $runLabel,
        '--network', 'none',
        '--read-only',
        '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges=true',
        '--cpus', '1',
        '--memory', '512m',
        '--pids-limit', '64',
        '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m',
        '--mount', ('type=bind,source={0},target=/input/capture,readonly' -f $fixture),
        '--entrypoint', '/bin/sh',
        $image, '-c', $probeCommand
    )
    $containerCleanupRequired = $true
    $nativeResult = Invoke-QuietNative { & $docker @createArguments } $nativeError
    if ($nativeResult.ExitCode -ne 0) { Fail-Verification 'probe_create_failed' }

    $nativeResult = Invoke-QuietNative { & $docker inspect $containerName } $nativeError
    if ($nativeResult.ExitCode -ne 0) { Fail-Verification 'probe_inspect_failed' }
    $inspectionText = $nativeResult.Output
    $inspection = ($inspectionText | ConvertFrom-Json)[0]
    Assert-True ($inspection.Config.User -eq '65532:65532') 'non_root_config_failed'
    Assert-True ($inspection.HostConfig.NetworkMode -eq 'none') 'network_none_failed'
    Assert-True ([bool]$inspection.HostConfig.ReadonlyRootfs) 'readonly_root_config_failed'
    Assert-True (@($inspection.HostConfig.CapDrop) -contains 'ALL') 'cap_drop_config_failed'
    Assert-True (@($inspection.HostConfig.SecurityOpt) -contains 'no-new-privileges=true') 'no_new_privileges_config_failed'
    Assert-True ([int64]$inspection.HostConfig.NanoCpus -eq 1000000000) 'cpu_limit_config_failed'
    Assert-True ([int64]$inspection.HostConfig.Memory -eq 536870912) 'memory_limit_config_failed'
    Assert-True ([int64]$inspection.HostConfig.PidsLimit -eq 64) 'pids_limit_config_failed'
    Assert-True (@($inspection.Mounts).Count -eq 1) 'mount_count_invalid'
    Assert-True ($inspection.Mounts[0].Type -eq 'bind' -and $inspection.Mounts[0].Destination -eq '/input/capture' -and -not [bool]$inspection.Mounts[0].RW) 'mount_policy_invalid'
    $tmpfsProperty = $inspection.HostConfig.Tmpfs.PSObject.Properties['/tmp']
    Assert-True ($null -ne $tmpfsProperty -and $tmpfsProperty.Value -match 'noexec' -and $tmpfsProperty.Value -match 'nosuid' -and $tmpfsProperty.Value -match 'nodev' -and $tmpfsProperty.Value -match 'size=16m') 'tmpfs_policy_invalid'

    $nativeResult = Invoke-QuietNative { & $docker start -a $containerName } $nativeError
    if ($nativeResult.ExitCode -ne 0) { Fail-Verification 'probe_run_failed' }
    $probeText = $nativeResult.Output -join "`n"
    $probe = [ordered]@{}
    foreach ($line in ($probeText -split "`r?`n")) {
        if ($line -notmatch '^([a-z_]+)=(.*)$') { Fail-Verification 'probe_output_invalid' }
        $probe[$Matches[1]] = $Matches[2]
    }
    Assert-True (Test-ExactKeys ([pscustomobject]$probe) @('uid', 'cap_eff', 'root_write', 'input_write', 'memory_max', 'pids_max', 'cpu_max')) 'probe_output_invalid'
    Assert-True ($probe.uid -eq '65532') 'non_root_runtime_failed'
    Assert-True ($probe.cap_eff -match '^0+$') 'cap_drop_runtime_failed'
    Assert-True ($probe.root_write -eq '0') 'readonly_root_runtime_failed'
    Assert-True ($probe.input_write -eq '0') 'readonly_input_runtime_failed'
    Assert-True ($probe.memory_max -eq '536870912') 'memory_limit_runtime_failed'
    Assert-True ($probe.pids_max -eq '64') 'pids_limit_runtime_failed'
    Assert-True ($probe.cpu_max -match '^([0-9]+)_\1$') 'cpu_limit_runtime_failed'

    $nativeResult = Invoke-QuietNative { & $docker ps -aq --filter ('label=' + $runLabel) } $nativeError
    if ($nativeResult.ExitCode -ne 0) { Fail-Verification 'residual_container_check_failed' }
    $remaining = $nativeResult.Output
    $remaining = @($remaining | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $residualContainers = $remaining.Count
    Assert-True ($residualContainers -eq 0) 'residual_container_failed'

    $verificationPassed = $true
}
catch {
}
finally {
    if ($null -ne $docker -and $containerCleanupRequired) {
        $cleanupResult = Invoke-QuietNative { & $docker ps -aq --filter ('label=' + $runLabel) } $nativeError
        $containerIds = $cleanupResult.Output
        foreach ($containerId in $containerIds) {
            if ($containerId -match '^[0-9a-f]{12,64}$') {
                $null = Invoke-QuietNative { & $docker rm -f $containerId } $nativeError
            }
        }
        $cleanupResult = Invoke-QuietNative { & $docker ps -aq --filter ('label=' + $runLabel) } $nativeError
        $postCleanupIds = $cleanupResult.Output
        if ($cleanupResult.ExitCode -ne 0) {
            $residualContainers = 1
            $verificationPassed = $false
            $script:FailureCode = 'cleanup_verification_failed'
        }
        else {
            $postCleanupIds = @($postCleanupIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            $residualContainers = $postCleanupIds.Count
            if ($residualContainers -ne 0) {
                $verificationPassed = $false
                $script:FailureCode = 'cleanup_failed'
            }
        }
    }
    $resolvedTempRoot = [System.IO.Path]::GetFullPath($tempRoot)
    $expectedPrefix = $tempBase.TrimEnd([char]'\', [char]'/') + [System.IO.Path]::DirectorySeparatorChar + 'pcap-sandbox-verification-'
    if ($resolvedTempRoot.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedTempRoot)) {
        Remove-Item -LiteralPath $resolvedTempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($verificationPassed -and $residualContainers -eq 0) {
    Write-Output 'pcap_sandbox_verification=passed network_none=1 readonly_root=1 non_root=1 cap_drop_all=1 no_new_privileges=1 resource_limits=1 payload_leaks=0 residual_containers=0'
    exit 0
}

Write-Output ('pcap_sandbox_verification=failed code={0} network_none=0 readonly_root=0 non_root=0 cap_drop_all=0 no_new_privileges=0 resource_limits=0 payload_leaks=0 residual_containers={1}' -f $script:FailureCode, $residualContainers)
exit 2
