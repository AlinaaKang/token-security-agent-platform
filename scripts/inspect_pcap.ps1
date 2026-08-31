[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$QuarantineRoot = 'E:\Codex\pcap-quarantine',

    [string]$DockerExecutable
)

$ErrorActionPreference = 'Stop'
$script:PublicErrorCodes = @(
    'docker_failed',
    'docker_timeout',
    'docker_unavailable',
    'input_changed',
    'input_not_regular_file',
    'input_outside_quarantine',
    'input_reparse_point',
    'invalid_report_schema',
    'unexpected_failure',
    'unsupported_capture_extension'
)

function Fail-Preflight {
    param([Parameter(Mandatory = $true)][string]$Code)
    throw [System.InvalidOperationException]::new($Code)
}

function Resolve-DockerExecutable {
    param([string]$Override)

    if (-not [string]::IsNullOrWhiteSpace($Override)) {
        if (Test-Path -LiteralPath $Override -PathType Leaf) {
            return [System.IO.Path]::GetFullPath($Override)
        }
        Fail-Preflight 'docker_unavailable'
    }

    $command = Get-Command docker -ErrorAction SilentlyContinue
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace($command.Source)) {
        return $command.Source
    }

    $candidates = @(
        [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Programs\DockerDesktop\resources\bin\docker.exe'),
        [System.IO.Path]::Combine($env:ProgramFiles, 'Docker\Docker\resources\bin\docker.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    Fail-Preflight 'docker_unavailable'
}

function Get-PropertyNames {
    param([Parameter(Mandatory = $true)]$Value)

    if ($null -eq $Value -or $Value -isnot [pscustomobject]) {
        Fail-Preflight 'invalid_report_schema'
    }
    return @($Value.PSObject.Properties | ForEach-Object { $_.Name })
}

function Test-ExactPropertyNames {
    param(
        [Parameter(Mandatory = $true)][string[]]$Actual,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )

    if ($Actual.Count -ne $Expected.Count) {
        return $false
    }
    foreach ($name in $Expected) {
        if ($Actual -notcontains $name) {
            return $false
        }
    }
    return $true
}

function Test-IntegerInRange {
    param([Parameter(Mandatory = $true)]$Value)

    if ($Value -is [bool]) {
        return $false
    }
    if ($Value -isnot [byte] -and $Value -isnot [int16] -and $Value -isnot [int32] -and $Value -isnot [int64] -and $Value -isnot [uint16] -and $Value -isnot [uint32] -and $Value -isnot [uint64]) {
        return $false
    }
    return $Value -ge 0 -and $Value -le [int64]::MaxValue
}

function Test-FiniteNonnegativeNumber {
    param([Parameter(Mandatory = $true)]$Value)

    if ($Value -is [bool] -or ($Value -isnot [byte] -and $Value -isnot [int16] -and $Value -isnot [int32] -and $Value -isnot [int64] -and $Value -isnot [uint16] -and $Value -isnot [uint32] -and $Value -isnot [uint64] -and $Value -isnot [single] -and $Value -isnot [double] -and $Value -isnot [decimal])) {
        return $false
    }
    $number = [double]$Value
    return -not [double]::IsNaN($number) -and -not [double]::IsInfinity($number) -and $number -ge 0
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $stream = [System.IO.File]::OpenRead($LiteralPath)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $algorithm.ComputeHash($stream)
        return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

function Test-SortedUniqueStrings {
    param([Parameter(Mandatory = $true)]$Value)

    if ($Value -isnot [array]) {
        return $false
    }
    for ($index = 0; $index -lt $Value.Count; $index++) {
        if ($Value[$index] -isnot [string] -or [string]::IsNullOrEmpty($Value[$index])) {
            return $false
        }
        if ($index -gt 0 -and [string]::CompareOrdinal([string]$Value[$index - 1], [string]$Value[$index]) -ge 0) {
            return $false
        }
    }
    return $true
}

function Get-Policy {
    param(
        [Parameter(Mandatory = $true)][int64]$PacketCount,
        [Parameter(Mandatory = $true)]$ProtocolCounts
    )

    if ($PacketCount -eq 0) {
        return @('insufficient_evidence', @('no_packets'))
    }
    foreach ($protocol in @('http', 'http2', 'websocket')) {
        if ($ProtocolCounts.PSObject.Properties[$protocol] -and $ProtocolCounts.$protocol -gt 0) {
            return @('token_eligible', @('plaintext_application_protocol_observed'))
        }
    }
    foreach ($protocol in @('tls', 'quic')) {
        if ($ProtocolCounts.PSObject.Properties[$protocol] -and $ProtocolCounts.$protocol -gt 0) {
            return @('traffic_only', @('encrypted_transport_observed'))
        }
    }
    $total = 0
    foreach ($property in $ProtocolCounts.PSObject.Properties) {
        $total += [int64]$property.Value
    }
    if ($total -gt 0) {
        return @('traffic_only', @('network_traffic_only'))
    }
    return @('insufficient_evidence', @('no_supported_protocols'))
}

function ConvertTo-ValidatedReport {
    param([Parameter(Mandatory = $true)][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        Fail-Preflight 'invalid_report_schema'
    }
    try {
        $report = $Text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Fail-Preflight 'invalid_report_schema'
    }

    $reportKeys = @('schema_version', 'sha256', 'size_bytes', 'capture_format', 'packet_count', 'duration_seconds', 'link_types', 'protocol_counts', 'visibility', 'capability', 'reasons', 'tool_versions')
    if (-not (Test-ExactPropertyNames (Get-PropertyNames $report) $reportKeys)) {
        Fail-Preflight 'invalid_report_schema'
    }
    $forbiddenKeys = @('prompt', 'suffix', 'token_text', 'payload', 'cookie', 'authorization', 'url', 'domain', 'ip', 'port', 'path')
    foreach ($forbiddenKey in $forbiddenKeys) {
        if ((Get-PropertyNames $report) -contains $forbiddenKey) {
            Fail-Preflight 'invalid_report_schema'
        }
    }

    if ($report.schema_version -ne 1 -or -not (Test-IntegerInRange $report.schema_version)) { Fail-Preflight 'invalid_report_schema' }
    if ($report.sha256 -isnot [string] -or $report.sha256 -notmatch '^[0-9a-f]{64}$') { Fail-Preflight 'invalid_report_schema' }
    if (-not (Test-IntegerInRange $report.size_bytes) -or -not (Test-IntegerInRange $report.packet_count)) { Fail-Preflight 'invalid_report_schema' }
    if (@('pcap', 'pcapng') -notcontains $report.capture_format) { Fail-Preflight 'invalid_report_schema' }
    if (-not (Test-FiniteNonnegativeNumber $report.duration_seconds)) { Fail-Preflight 'invalid_report_schema' }
    if (-not (Test-SortedUniqueStrings $report.link_types)) { Fail-Preflight 'invalid_report_schema' }
    foreach ($linkType in $report.link_types) {
        if ($linkType -notmatch '^encap_[0-9]+$') { Fail-Preflight 'invalid_report_schema' }
    }

    $allowedProtocols = @('arp', 'dns', 'eth', 'http', 'http2', 'icmp', 'icmpv6', 'ip', 'ipv6', 'quic', 'sll', 'sll2', 'tcp', 'tls', 'udp', 'websocket')
    $protocolNames = Get-PropertyNames $report.protocol_counts
    for ($index = 0; $index -lt $protocolNames.Count; $index++) {
        $name = $protocolNames[$index]
        if ($allowedProtocols -notcontains $name -or -not (Test-IntegerInRange $report.protocol_counts.$name)) { Fail-Preflight 'invalid_report_schema' }
        if ($index -gt 0 -and [string]::CompareOrdinal($protocolNames[$index - 1], $name) -ge 0) { Fail-Preflight 'invalid_report_schema' }
    }

    $visibilityKeys = @('plaintext_application_protocol_observed', 'encrypted_transport_observed', 'tls_observed', 'quic_observed')
    if (-not (Test-ExactPropertyNames (Get-PropertyNames $report.visibility) $visibilityKeys)) { Fail-Preflight 'invalid_report_schema' }
    $expectedVisibility = [ordered]@{
        plaintext_application_protocol_observed = (($report.protocol_counts.http -gt 0) -or ($report.protocol_counts.http2 -gt 0) -or ($report.protocol_counts.websocket -gt 0))
        encrypted_transport_observed = (($report.protocol_counts.tls -gt 0) -or ($report.protocol_counts.quic -gt 0))
        tls_observed = ($report.protocol_counts.tls -gt 0)
        quic_observed = ($report.protocol_counts.quic -gt 0)
    }
    foreach ($name in $visibilityKeys) {
        if ($report.visibility.$name -isnot [bool] -or $report.visibility.$name -ne $expectedVisibility[$name]) { Fail-Preflight 'invalid_report_schema' }
    }

    if (@('token_eligible', 'traffic_only', 'insufficient_evidence') -notcontains $report.capability -or -not (Test-SortedUniqueStrings $report.reasons)) { Fail-Preflight 'invalid_report_schema' }
    $allowedReasons = @('plaintext_application_protocol_observed', 'encrypted_transport_observed', 'network_traffic_only', 'no_packets', 'no_supported_protocols')
    foreach ($reason in $report.reasons) {
        if ($allowedReasons -notcontains $reason) { Fail-Preflight 'invalid_report_schema' }
    }
    $expectedPolicy = Get-Policy ([int64]$report.packet_count) $report.protocol_counts
    if ($report.capability -ne $expectedPolicy[0] -or $report.reasons.Count -ne $expectedPolicy[1].Count -or $report.reasons[0] -ne $expectedPolicy[1][0]) { Fail-Preflight 'invalid_report_schema' }

    if (-not (Test-ExactPropertyNames (Get-PropertyNames $report.tool_versions) @('tshark'))) { Fail-Preflight 'invalid_report_schema' }
    if ($report.tool_versions.tshark -isnot [string] -or $report.tool_versions.tshark -notmatch '^(?:tshark|TShark [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$') { Fail-Preflight 'invalid_report_schema' }

    return $report
}

function Save-Report {
    param(
        [Parameter(Mandatory = $true)]$Report,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $stableReport = [ordered]@{
        schema_version = $Report.schema_version
        sha256 = $Report.sha256
        size_bytes = $Report.size_bytes
        capture_format = $Report.capture_format
        packet_count = $Report.packet_count
        duration_seconds = $Report.duration_seconds
        link_types = @($Report.link_types)
        protocol_counts = [ordered]@{}
        visibility = [ordered]@{
            plaintext_application_protocol_observed = $Report.visibility.plaintext_application_protocol_observed
            encrypted_transport_observed = $Report.visibility.encrypted_transport_observed
            tls_observed = $Report.visibility.tls_observed
            quic_observed = $Report.visibility.quic_observed
        }
        capability = $Report.capability
        reasons = @($Report.reasons)
        tool_versions = [ordered]@{ tshark = $Report.tool_versions.tshark }
    }
    foreach ($property in $Report.protocol_counts.PSObject.Properties) {
        $stableReport.protocol_counts[$property.Name] = $property.Value
    }
    $json = $stableReport | ConvertTo-Json -Depth 5 -Compress
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($OutputPath, $json, $utf8WithoutBom)
}

try {
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($QuarantineRoot)
    $inputRoot = [System.IO.Path]::Combine($fullRoot, 'input')
    $inputPrefix = $inputRoot.TrimEnd([char]'\', [char]'/') + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($inputPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        Fail-Preflight 'input_outside_quarantine'
    }
    try {
        $attributes = [System.IO.File]::GetAttributes($fullPath)
    }
    catch {
        Fail-Preflight 'input_not_regular_file'
    }
    if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { Fail-Preflight 'input_reparse_point' }
    if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0 -or -not [System.IO.File]::Exists($fullPath)) { Fail-Preflight 'input_not_regular_file' }
    if ([System.IO.Path]::GetExtension($fullPath) -notin @('.pcap', '.pcapng')) { Fail-Preflight 'unsupported_capture_extension' }

    $dockerExecutable = Resolve-DockerExecutable $DockerExecutable
    $dockerArgs = @(
        'run', '--rm',
        '--network', 'none',
        '--read-only',
        '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges=true',
        '--cpus', '1',
        '--memory', '512m',
        '--pids-limit', '64',
        '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m',
        '--mount', ("type=bind,source={0},target=/input/capture,readonly" -f $fullPath),
        'token-security-pcap-preflight:local'
    )

    $processExecutable = $dockerExecutable
    $processArguments = @($dockerArgs | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }) -join ' '
    if ([System.IO.Path]::GetExtension($dockerExecutable) -in @('.cmd', '.bat')) {
        if ($dockerExecutable.Contains('%') -or $dockerExecutable.Contains('!') -or $fullPath.Contains('%') -or $fullPath.Contains('!')) {
            Fail-Preflight 'docker_unavailable'
        }
        $quotedArguments = @($dockerArgs | ForEach-Object { '"' + ($_ -replace '"', '""') + '"' })
        $commandLine = 'call "' + ($dockerExecutable -replace '"', '""') + '" ' + ($quotedArguments -join ' ')
        $processExecutable = $env:ComSpec
        $processArguments = '/d /v:off /s /c "' + $commandLine + '"'
    }

    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    $stdoutStream = $null
    $stderrStream = $null
    $process = $null
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $processExecutable
        $startInfo.Arguments = $processArguments
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { Fail-Preflight 'docker_failed' }

        $stdoutStream = New-Object System.IO.FileStream($stdoutFile, [System.IO.FileMode]::Truncate, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $stderrStream = New-Object System.IO.FileStream($stderrFile, [System.IO.FileMode]::Truncate, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $stdoutCopy = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)
        $stderrCopy = $process.StandardError.BaseStream.CopyToAsync($stderrStream)

        if (-not $process.WaitForExit(150000)) {
            try { $process.Kill() } catch {}
            $process.WaitForExit()
            Fail-Preflight 'docker_timeout'
        }
        $process.WaitForExit()
        [System.Threading.Tasks.Task]::WaitAll(@($stdoutCopy, $stderrCopy))
        $stdoutStream.Flush()
        $stderrStream.Flush()
        if ($process.ExitCode -ne 0) { Fail-Preflight 'docker_failed' }
        $stdoutStream.Dispose()
        $stdoutStream = $null
        $stderrStream.Dispose()
        $stderrStream = $null
        $stdout = [System.IO.File]::ReadAllText($stdoutFile)
    }
    finally {
        if ($null -ne $stdoutStream) { $stdoutStream.Dispose() }
        if ($null -ne $stderrStream) { $stderrStream.Dispose() }
        if ($null -ne $process) { $process.Dispose() }
        if ($null -ne $stdoutFile) { Remove-Item -LiteralPath $stdoutFile -Force -ErrorAction SilentlyContinue }
        if ($null -ne $stderrFile) { Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue }
    }

    $report = ConvertTo-ValidatedReport $stdout
    $postRunHash = Get-Sha256Hex $fullPath
    if ($postRunHash -ne $report.sha256) { Fail-Preflight 'input_changed' }

    $outputDirectory = [System.IO.Path]::Combine($fullRoot, 'output')
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    $reportPath = [System.IO.Path]::Combine($outputDirectory, ('pcap-preflight-{0}.json' -f $report.sha256.Substring(0, 16)))
    Save-Report $report $reportPath
    exit 0
}
catch {
    $code = 'unexpected_failure'
    if ($script:PublicErrorCodes -contains $_.Exception.Message) {
        $code = $_.Exception.Message
    }
    Write-Output ('pcap_preflight_error={0}' -f $code)
    exit 2
}
