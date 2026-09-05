[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$QuarantineRoot = 'E:\Codex\pcap-quarantine',

    [string]$DockerExecutable,

    [ValidateSet('Preflight', 'HttpDetection')]
    [string]$Mode = 'Preflight'
)

$ErrorActionPreference = 'Stop'
$script:PublicErrorCodes = @(
    'docker_failed',
    'docker_timeout',
    'capture_invalid',
    'docker_unavailable',
    'input_changed',
    'input_not_regular_file',
    'input_outside_quarantine',
    'input_reparse_point',
    'invalid_report_schema',
    'output_reparse_point',
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

function Assert-NoReparsePoints {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$Code
    )

    $current = [System.IO.Path]::GetFullPath($LiteralPath)
    $pathRoot = [System.IO.Path]::GetPathRoot($current).TrimEnd([char]'\', [char]'/')
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if (Test-Path -LiteralPath $current) {
            try {
                $attributes = [System.IO.File]::GetAttributes($current)
            }
            catch {
                Fail-Preflight $Code
            }
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail-Preflight $Code
            }
        }

        $trimmed = $current.TrimEnd([char]'\', [char]'/')
        if ($trimmed.Equals($pathRoot, [System.StringComparison]::OrdinalIgnoreCase)) { break }
        $parent = [System.IO.Directory]::GetParent($trimmed)
        if ($null -eq $parent) { break }
        $current = $parent.FullName
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

function Test-UniqueStrings {
    param([Parameter(Mandatory = $true)]$Value)

    if ($Value -isnot [array] -or $Value.Count -lt 1) {
        return $false
    }
    $seen = @{}
    foreach ($item in $Value) {
        if ($item -isnot [string] -or [string]::IsNullOrEmpty($item) -or $seen.ContainsKey($item)) {
            return $false
        }
        $seen[$item] = $true
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

function ConvertTo-ValidatedDetectionReport {
    param([Parameter(Mandatory = $true)][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { Fail-Preflight 'invalid_report_schema' }
    try {
        $report = $Text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Fail-Preflight 'invalid_report_schema'
    }
    if (-not (Test-ExactPropertyNames (Get-PropertyNames $report) @('schema_version', 'verified_packet_count', 'evidence'))) {
        Fail-Preflight 'invalid_report_schema'
    }
    if ($report.schema_version -ne 1 -or -not (Test-IntegerInRange $report.schema_version)) { Fail-Preflight 'invalid_report_schema' }
    if (-not (Test-IntegerInRange $report.verified_packet_count)) { Fail-Preflight 'invalid_report_schema' }
    if ($report.evidence -isnot [array] -or $report.evidence.Count -gt 160) { Fail-Preflight 'invalid_report_schema' }

    $seenEvidence = @{}
    foreach ($item in $report.evidence) {
        $expectedKeys = @('evidence_id', 'granularity', 'verified_packet_count', 'start_packet', 'end_packet', 'start_offset_ms', 'end_offset_ms', 'attack_candidate', 'detector', 'confidence', 'supporting_signals')
        if (-not (Test-ExactPropertyNames (Get-PropertyNames $item) $expectedKeys)) { Fail-Preflight 'invalid_report_schema' }
        if ($item.evidence_id -isnot [string] -or $item.evidence_id -notmatch '^evidence_[0-9a-f]{32}$' -or $seenEvidence.ContainsKey($item.evidence_id)) { Fail-Preflight 'invalid_report_schema' }
        $seenEvidence[$item.evidence_id] = $true
        if ($item.granularity -ne 'request' -or $item.detector -ne 'http_rule') { Fail-Preflight 'invalid_report_schema' }
        if (@('sql_injection', 'command_injection', 'path_traversal') -notcontains $item.attack_candidate) { Fail-Preflight 'invalid_report_schema' }
        foreach ($integerField in @('verified_packet_count', 'start_packet', 'end_packet', 'start_offset_ms', 'end_offset_ms')) {
            if (-not (Test-IntegerInRange $item.$integerField)) { Fail-Preflight 'invalid_report_schema' }
        }
        if ($item.verified_packet_count -ne $report.verified_packet_count -or $item.start_packet -lt 1 -or $item.start_packet -gt $item.end_packet -or $item.end_packet -gt $report.verified_packet_count) { Fail-Preflight 'invalid_report_schema' }
        if ($item.start_offset_ms -gt $item.end_offset_ms) { Fail-Preflight 'invalid_report_schema' }
        if (-not (Test-FiniteNonnegativeNumber $item.confidence) -or [double]$item.confidence -gt 1) { Fail-Preflight 'invalid_report_schema' }
        if (-not (Test-UniqueStrings $item.supporting_signals) -or $item.supporting_signals.Count -gt 8) { Fail-Preflight 'invalid_report_schema' }
        foreach ($signal in $item.supporting_signals) {
            if (@('sql_syntax_pattern', 'command_syntax_pattern', 'path_traversal_pattern', 'request_boundary') -notcontains $signal) { Fail-Preflight 'invalid_report_schema' }
        }
    }
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

function Save-DetectionReport {
    param(
        [Parameter(Mandatory = $true)]$Report,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $stableEvidence = @()
    foreach ($item in $Report.evidence) {
        $stableEvidence += [ordered]@{
            evidence_id = $item.evidence_id
            granularity = $item.granularity
            verified_packet_count = $item.verified_packet_count
            start_packet = $item.start_packet
            end_packet = $item.end_packet
            start_offset_ms = $item.start_offset_ms
            end_offset_ms = $item.end_offset_ms
            attack_candidate = $item.attack_candidate
            detector = $item.detector
            confidence = $item.confidence
            supporting_signals = @($item.supporting_signals)
        }
    }
    $stableReport = [ordered]@{
        schema_version = $Report.schema_version
        verified_packet_count = $Report.verified_packet_count
        evidence = $stableEvidence
    }
    $json = $stableReport | ConvertTo-Json -Depth 5 -Compress
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($OutputPath, $json, $utf8WithoutBom)
    return $json
}

try {
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($QuarantineRoot)
    $inputRoot = [System.IO.Path]::Combine($fullRoot, 'input')
    $inputPrefix = $inputRoot.TrimEnd([char]'\', [char]'/') + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($inputPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        Fail-Preflight 'input_outside_quarantine'
    }
    Assert-NoReparsePoints $fullPath 'input_reparse_point'
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
    $preRunHash = Get-Sha256Hex $fullPath
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
    if ($Mode -eq 'HttpDetection') {
        $dockerArgs += 'detect-http'
    }

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
        $stdoutStream.Dispose()
        $stdoutStream = $null
        $stderrStream.Dispose()
        $stderrStream = $null
        $stdout = [System.IO.File]::ReadAllText($stdoutFile)
        $stderr = [System.IO.File]::ReadAllText($stderrFile)
        if ($process.ExitCode -ne 0) {
            if ($Mode -eq 'HttpDetection' -and $stderr -match '(?m)^pcap_detection_error=capture_invalid\b') {
                Fail-Preflight 'capture_invalid'
            }
            Fail-Preflight 'docker_failed'
        }
    }
    finally {
        if ($null -ne $stdoutStream) { $stdoutStream.Dispose() }
        if ($null -ne $stderrStream) { $stderrStream.Dispose() }
        if ($null -ne $process) { $process.Dispose() }
        if ($null -ne $stdoutFile) { Remove-Item -LiteralPath $stdoutFile -Force -ErrorAction SilentlyContinue }
        if ($null -ne $stderrFile) { Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue }
    }

    $postRunHash = Get-Sha256Hex $fullPath
    if ($postRunHash -ne $preRunHash) { Fail-Preflight 'input_changed' }

    $outputDirectory = [System.IO.Path]::Combine($fullRoot, 'output')
    Assert-NoReparsePoints $outputDirectory 'output_reparse_point'
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    Assert-NoReparsePoints $outputDirectory 'output_reparse_point'
    if ($Mode -eq 'HttpDetection') {
        $report = ConvertTo-ValidatedDetectionReport $stdout
        $reportPath = [System.IO.Path]::Combine($outputDirectory, ('pcap-detection-{0}.json' -f [guid]::NewGuid().ToString('N')))
        Assert-NoReparsePoints $reportPath 'output_reparse_point'
        $publicJson = Save-DetectionReport $report $reportPath
        Write-Output $publicJson
        exit 0
    }

    $report = ConvertTo-ValidatedReport $stdout
    if ($postRunHash -ne $report.sha256) { Fail-Preflight 'input_changed' }
    $reportPath = [System.IO.Path]::Combine($outputDirectory, ('pcap-preflight-{0}.json' -f $report.sha256.Substring(0, 16)))
    Assert-NoReparsePoints $reportPath 'output_reparse_point'
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
