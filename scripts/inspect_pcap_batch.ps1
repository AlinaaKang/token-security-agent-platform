[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$QuarantineRoot,
    [Parameter(Mandatory = $true)][ValidatePattern('^batch_[0-9a-f]{32}$')][string]$BatchId,
    [Parameter(Mandatory = $true)][ValidatePattern('^state_[0-9a-f]{32}$')][string]$StateId,
    [ValidateRange(1, 20)][int]$MaxFiles = 20,
    [Parameter(Mandatory = $true)][string]$InspectorScript,
    [string]$DockerExecutable
)

$ErrorActionPreference = 'Stop'
$script:PublicErrorCodes = @(
    'input_reparse_point',
    'invalid_report_schema',
    'invalid_state',
    'output_reparse_point',
    'state_reparse_point',
    'unexpected_failure'
)
$script:AllowedProtocols = @('arp', 'dns', 'eth', 'http', 'http2', 'icmp', 'icmpv6', 'ip', 'ipv6', 'quic', 'sll', 'sll2', 'tcp', 'tls', 'udp', 'websocket')
$script:ChildReportKeys = @('schema_version', 'sha256', 'size_bytes', 'capture_format', 'packet_count', 'duration_seconds', 'link_types', 'protocol_counts', 'visibility', 'capability', 'reasons', 'tool_versions')
$script:VisibilityKeys = @('plaintext_application_protocol_observed', 'encrypted_transport_observed', 'tls_observed', 'quic_observed')
$script:PrivateStateKeys = @('schema_version', 'state_id', 'entries')
$script:PrivateStateEntryKeys = @('internal_path', 'sha256', 'size_bytes', 'last_result', 'capture_id', 'packet_count', 'protocol_counts', 'visibility', 'capability', 'error_code')
$script:LegacyPrivateStateKeys = @('schema_version', 'entries')
$script:LegacyPrivateStateEntryKeys = @('batch_id', 'internal_path', 'sha256', 'size_bytes', 'last_result', 'capture_id', 'packet_count', 'protocol_counts', 'visibility', 'capability', 'error_code')

function Fail-Batch {
    param([Parameter(Mandatory = $true)][string]$Code)
    throw [System.InvalidOperationException]::new($Code)
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
            try { $attributes = [System.IO.File]::GetAttributes($current) }
            catch { Fail-Batch $Code }
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { Fail-Batch $Code }
        }
        $trimmed = $current.TrimEnd([char]'\', [char]'/')
        if ($trimmed.Equals($pathRoot, [System.StringComparison]::OrdinalIgnoreCase)) { break }
        $parent = [System.IO.Directory]::GetParent($trimmed)
        if ($null -eq $parent) { break }
        $current = $parent.FullName
    }
}

function Ensure-SafeDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$Code
    )
    Assert-NoReparsePoints $LiteralPath $Code
    New-Item -ItemType Directory -Path $LiteralPath -Force | Out-Null
    Assert-NoReparsePoints $LiteralPath $Code
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    $stream = [System.IO.File]::OpenRead($LiteralPath)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { return (($algorithm.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}

function Get-PropertyNames {
    param([Parameter(Mandatory = $true)]$Value)
    if ($null -eq $Value -or $Value -isnot [pscustomobject]) { Fail-Batch 'invalid_report_schema' }
    return @($Value.PSObject.Properties | ForEach-Object { $_.Name })
}

function Test-ExactPropertyNames {
    param([Parameter(Mandatory = $true)][string[]]$Actual, [Parameter(Mandatory = $true)][string[]]$Expected)
    if ($Actual.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) { if ($Actual -notcontains $name) { return $false } }
    return $true
}

function Test-NonnegativeInteger {
    param([Parameter(Mandatory = $true)]$Value)
    if ($Value -is [bool]) { return $false }
    if ($Value -isnot [byte] -and $Value -isnot [int16] -and $Value -isnot [int32] -and $Value -isnot [int64] -and $Value -isnot [uint16] -and $Value -isnot [uint32] -and $Value -isnot [uint64]) { return $false }
    return $Value -ge 0 -and $Value -le [int64]::MaxValue
}

function Get-SafeCaptureFiles {
    param([Parameter(Mandatory = $true)][System.IO.DirectoryInfo]$InputRoot)
    $queue = [System.Collections.Generic.Queue[System.IO.DirectoryInfo]]::new()
    $queue.Enqueue($InputRoot)
    while ($queue.Count -gt 0) {
        $directory = $queue.Dequeue()
        foreach ($entry in $directory.GetFileSystemInfos()) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { Fail-Batch 'input_reparse_point' }
            if ($entry -is [System.IO.DirectoryInfo]) { $queue.Enqueue($entry); continue }
            if ($entry -is [System.IO.FileInfo] -and $entry.Extension.ToLowerInvariant() -in @('.pcap', '.pcapng')) { $entry }
        }
    }
}

function Get-OrderedCaptureFiles {
    param([Parameter(Mandatory = $true)][System.IO.DirectoryInfo]$InputRoot)
    $prefix = $InputRoot.FullName.TrimEnd([char]'\', [char]'/') + [System.IO.Path]::DirectorySeparatorChar
    $items = [System.Collections.ArrayList]::new()
    foreach ($file in @(Get-SafeCaptureFiles $InputRoot)) {
        $ordinal = $file.FullName.Substring($prefix.Length)
        [void]$items.Add([pscustomobject]@{ File = $file; Ordinal = $ordinal })
    }
    for ($index = 1; $index -lt $items.Count; $index++) {
        $candidate = $items[$index]
        $position = $index - 1
        while ($position -ge 0 -and (($items[$position].File.Length -gt $candidate.File.Length) -or (($items[$position].File.Length -eq $candidate.File.Length) -and [string]::CompareOrdinal($items[$position].Ordinal, $candidate.Ordinal) -gt 0))) {
            $items[$position + 1] = $items[$position]
            $position--
        }
        $items[$position + 1] = $candidate
    }
    return @($items)
}

function Assert-ValidPrivateStateEntry {
    param(
        [Parameter(Mandatory = $true)]$Entry,
        [Parameter(Mandatory = $true)][string[]]$ExpectedKeys,
        [switch]$RequireBatchId
    )
    if ($Entry -isnot [pscustomobject] -or -not (Test-ExactPropertyNames (@($Entry.PSObject.Properties | ForEach-Object { $_.Name })) $ExpectedKeys)) { Fail-Batch 'invalid_state' }
    if ($RequireBatchId -and ($Entry.batch_id -isnot [string] -or $Entry.batch_id -notmatch '^batch_[0-9a-f]{32}$')) { Fail-Batch 'invalid_state' }
    if ($Entry.internal_path -isnot [string] -or [string]::IsNullOrEmpty($Entry.internal_path)) { Fail-Batch 'invalid_state' }
    if ($Entry.sha256 -isnot [string] -or $Entry.sha256 -notmatch '^[0-9a-f]{64}$' -or -not (Test-NonnegativeInteger $Entry.size_bytes)) { Fail-Batch 'invalid_state' }
    if (@('succeeded', 'failed') -notcontains $Entry.last_result -or $Entry.capture_id -isnot [string] -or $Entry.capture_id -notmatch '^capture_[0-9a-f]{32}$' -or -not (Test-NonnegativeInteger $Entry.packet_count)) { Fail-Batch 'invalid_state' }
    if ($Entry.protocol_counts -isnot [pscustomobject] -or $Entry.visibility -isnot [pscustomobject]) { Fail-Batch 'invalid_state' }
    foreach ($name in @($Entry.protocol_counts.PSObject.Properties | ForEach-Object { $_.Name })) {
        if ($script:AllowedProtocols -notcontains $name -or -not (Test-NonnegativeInteger $Entry.protocol_counts.$name)) { Fail-Batch 'invalid_state' }
    }
    if (-not (Test-ExactPropertyNames (@($Entry.visibility.PSObject.Properties | ForEach-Object { $_.Name })) $script:VisibilityKeys)) { Fail-Batch 'invalid_state' }
    foreach ($name in $script:VisibilityKeys) { if ($Entry.visibility.$name -isnot [bool]) { Fail-Batch 'invalid_state' } }
    if ($null -ne $Entry.capability -and @('token_eligible', 'traffic_only', 'insufficient_evidence') -notcontains $Entry.capability) { Fail-Batch 'invalid_state' }
    if ($Entry.capability -eq 'token_eligible' -and -not $Entry.visibility.plaintext_application_protocol_observed) { Fail-Batch 'invalid_state' }
    if ($null -ne $Entry.error_code -and ($Entry.error_code -isnot [string] -or $Entry.error_code -notmatch '^[a-z0-9_]+$')) { Fail-Batch 'invalid_state' }
    if ($Entry.last_result -eq 'succeeded' -and ($null -eq $Entry.capability -or $null -ne $Entry.error_code)) { Fail-Batch 'invalid_state' }
}

function Assert-ValidPrivateState {
    param([Parameter(Mandatory = $true)]$State)
    if ($null -eq $State -or $State -isnot [pscustomobject] -or -not (Test-ExactPropertyNames (@($State.PSObject.Properties | ForEach-Object { $_.Name })) $script:PrivateStateKeys)) { Fail-Batch 'invalid_state' }
    if ($State.schema_version -ne 2 -or $State.state_id -isnot [string] -or $State.state_id -notmatch '^state_[0-9a-f]{32}$' -or $null -eq $State.entries) { Fail-Batch 'invalid_state' }
    foreach ($entry in @($State.entries)) { Assert-ValidPrivateStateEntry $entry $script:PrivateStateEntryKeys }
}

function Convert-LegacyPrivateState {
    param([Parameter(Mandatory = $true)]$State)
    if ($State -isnot [pscustomobject] -or -not (Test-ExactPropertyNames (@($State.PSObject.Properties | ForEach-Object { $_.Name })) $script:LegacyPrivateStateKeys) -or $State.schema_version -ne 1 -or $null -eq $State.entries) { Fail-Batch 'invalid_state' }
    $migrated = [System.Collections.ArrayList]::new()
    foreach ($entry in @($State.entries)) {
        Assert-ValidPrivateStateEntry $entry $script:LegacyPrivateStateEntryKeys -RequireBatchId
        $migrated = [System.Collections.ArrayList]@($migrated | Where-Object { $_.internal_path -ne $entry.internal_path })
        [void]$migrated.Add([ordered]@{
            internal_path = $entry.internal_path
            sha256 = $entry.sha256
            size_bytes = [int64]$entry.size_bytes
            last_result = $entry.last_result
            capture_id = $entry.capture_id
            packet_count = [int64]$entry.packet_count
            protocol_counts = $entry.protocol_counts
            visibility = $entry.visibility
            capability = $entry.capability
            error_code = $entry.error_code
        })
    }
    return [pscustomobject][ordered]@{ schema_version = 2; state_id = $StateId; entries = @($migrated) }
}

function Read-PrivateState {
    param([Parameter(Mandatory = $true)][string]$StatePath)
    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
        return [pscustomobject]@{ schema_version = 2; state_id = $StateId; entries = @() }
    }
    try { $state = [System.IO.File]::ReadAllText($StatePath) | ConvertFrom-Json -ErrorAction Stop }
    catch { Fail-Batch 'invalid_state' }
    if ($state.schema_version -eq 1) { return Convert-LegacyPrivateState $state }
    Assert-ValidPrivateState $state
    if ($state.state_id -ne $StateId) {
        return [pscustomobject]@{ schema_version = 2; state_id = $StateId; entries = @() }
    }
    return $state
}

function Save-AtomicJson {
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Destination)
    $directory = [System.IO.Path]::GetDirectoryName($Destination)
    $temporary = Join-Path $directory (([System.IO.Path]::GetFileName($Destination)) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $json = $Value | ConvertTo-Json -Depth 8 -Compress
        [System.IO.File]::WriteAllText($temporary, $json, [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Destination -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
    }
}

function Get-DefaultEvidence {
    param([Parameter(Mandatory = $true)][string]$CaptureId, [Parameter(Mandatory = $true)][string]$Status, [string]$ErrorCode)
    return [ordered]@{
        capture_id = $CaptureId
        status = $Status
        packet_count = 0
        protocol_counts = [ordered]@{}
        visibility = [ordered]@{
            plaintext_application_protocol_observed = $false
            encrypted_transport_observed = $false
            tls_observed = $false
            quic_observed = $false
        }
        capability = $null
        error_code = $ErrorCode
    }
}

function Convert-ChildReportToEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$ReportPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha,
        [Parameter(Mandatory = $true)][int64]$ExpectedSize,
        [Parameter(Mandatory = $true)][string]$CaptureId
    )
    try { $report = [System.IO.File]::ReadAllText($ReportPath) | ConvertFrom-Json -ErrorAction Stop }
    catch { Fail-Batch 'invalid_report_schema' }
    if (-not (Test-ExactPropertyNames (Get-PropertyNames $report) $script:ChildReportKeys)) { Fail-Batch 'invalid_report_schema' }
    if ($report.schema_version -ne 1 -or $report.sha256 -ne $ExpectedSha -or $report.size_bytes -ne $ExpectedSize) { Fail-Batch 'invalid_report_schema' }
    if (-not (Test-NonnegativeInteger $report.packet_count)) { Fail-Batch 'invalid_report_schema' }
    $protocolNames = Get-PropertyNames $report.protocol_counts
    $publicProtocols = [ordered]@{}
    foreach ($name in $protocolNames) {
        if ($script:AllowedProtocols -notcontains $name -or -not (Test-NonnegativeInteger $report.protocol_counts.$name)) { Fail-Batch 'invalid_report_schema' }
        $publicProtocols[$name] = $report.protocol_counts.$name
    }
    if (-not (Test-ExactPropertyNames (Get-PropertyNames $report.visibility) $script:VisibilityKeys)) { Fail-Batch 'invalid_report_schema' }
    foreach ($name in $script:VisibilityKeys) { if ($report.visibility.$name -isnot [bool]) { Fail-Batch 'invalid_report_schema' } }
    if (@('token_eligible', 'traffic_only', 'insufficient_evidence') -notcontains $report.capability) { Fail-Batch 'invalid_report_schema' }
    if ($report.capability -eq 'token_eligible' -and -not $report.visibility.plaintext_application_protocol_observed) { Fail-Batch 'invalid_report_schema' }
    return [ordered]@{
        capture_id = $CaptureId
        status = 'succeeded'
        packet_count = [int64]$report.packet_count
        protocol_counts = $publicProtocols
        visibility = [ordered]@{
            plaintext_application_protocol_observed = $report.visibility.plaintext_application_protocol_observed
            encrypted_transport_observed = $report.visibility.encrypted_transport_observed
            tls_observed = $report.visibility.tls_observed
            quic_observed = $report.visibility.quic_observed
        }
        capability = $report.capability
        error_code = $null
    }
}

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append([char]34)
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]92) {
            $backslashes++
            continue
        }
        if ($character -eq [char]34) {
            [void]$builder.Append([char]92, ($backslashes * 2) + 1)
        }
        elseif ($backslashes -gt 0) {
            [void]$builder.Append([char]92, $backslashes)
        }
        [void]$builder.Append($character)
        $backslashes = 0
    }
    if ($backslashes -gt 0) { [void]$builder.Append([char]92, $backslashes * 2) }
    [void]$builder.Append([char]34)
    return $builder.ToString()
}

function Invoke-Inspector {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$CapturePath,
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$Docker
    )
    $powershell = [System.IO.Path]::Combine($env:SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', (Quote-ProcessArgument $ScriptPath), '-Path', (Quote-ProcessArgument $CapturePath), '-QuarantineRoot', (Quote-ProcessArgument $Root))
    if (-not [string]::IsNullOrWhiteSpace($Docker)) { $arguments += @('-DockerExecutable', (Quote-ProcessArgument $Docker)) }
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $powershell
    $startInfo.Arguments = ($arguments -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { return 1 }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        [void]$stdout.Result
        [void]$stderr.Result
        return $process.ExitCode
    }
    finally { $process.Dispose() }
}

function Find-StateEntry {
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)][string]$InternalPath)
    foreach ($entry in @($State.entries)) {
        if ($entry.internal_path -eq $InternalPath) { return $entry }
    }
    return $null
}

try {
    $fullRoot = [System.IO.Path]::GetFullPath($QuarantineRoot)
    $inputPath = [System.IO.Path]::Combine($fullRoot, 'input')
    $outputPath = [System.IO.Path]::Combine($fullRoot, 'output')
    $statePath = [System.IO.Path]::Combine($fullRoot, 'state')
    Ensure-SafeDirectory $inputPath 'input_reparse_point'
    Ensure-SafeDirectory $outputPath 'output_reparse_point'
    Ensure-SafeDirectory $statePath 'state_reparse_point'
    $privateStatePath = [System.IO.Path]::Combine($statePath, 'pcap-batch-private.json')
    Assert-NoReparsePoints $privateStatePath 'state_reparse_point'
    $state = Read-PrivateState $privateStatePath
    $cancelPath = [System.IO.Path]::Combine($statePath, ($BatchId + '.cancel'))
    if (Test-Path -LiteralPath $cancelPath -PathType Leaf) {
        Remove-Item -LiteralPath $cancelPath -Force -ErrorAction SilentlyContinue
        $selected = @()
    }
    else {
        $selected = [System.Collections.ArrayList]::new()
        foreach ($candidate in @(Get-OrderedCaptureFiles (Get-Item -LiteralPath $inputPath))) {
            Assert-NoReparsePoints $candidate.File.FullName 'input_reparse_point'
            if (Test-Path -LiteralPath $cancelPath -PathType Leaf) {
                Remove-Item -LiteralPath $cancelPath -Force -ErrorAction SilentlyContinue
                $selected.Clear()
                break
            }
            $currentSha = Get-Sha256Hex $candidate.File.FullName
            $previous = Find-StateEntry $state $candidate.Ordinal
            if ($null -ne $previous -and $previous.last_result -eq 'succeeded' -and $previous.sha256 -eq $currentSha -and $previous.size_bytes -eq $candidate.File.Length) { continue }
            [void]$selected.Add([pscustomobject]@{
                File = $candidate.File
                Ordinal = $candidate.Ordinal
                CurrentSha = $currentSha
                Previous = $previous
            })
            if ($selected.Count -ge $MaxFiles) { break }
        }
    }
    $captures = [System.Collections.ArrayList]::new()
    $updatedEntries = [System.Collections.ArrayList]::new()
    foreach ($entry in @($state.entries)) { [void]$updatedEntries.Add($entry) }

    foreach ($candidate in $selected) {
        Assert-NoReparsePoints $candidate.File.FullName 'input_reparse_point'
        if (Test-Path -LiteralPath $cancelPath -PathType Leaf) {
            Remove-Item -LiteralPath $cancelPath -Force -ErrorAction SilentlyContinue
            break
        }
        $currentSha = $candidate.CurrentSha
        $previous = $candidate.Previous
        $captureId = if ($null -ne $previous -and $previous.capture_id -match '^capture_[0-9a-f]{32}$') { $previous.capture_id } else { 'capture_' + [Guid]::NewGuid().ToString('N') }
        $childPath = [System.IO.Path]::Combine($outputPath, ('pcap-preflight-' + $currentSha.Substring(0, 16) + '.json'))
        $result = $null
        try {
            $exitCode = Invoke-Inspector $InspectorScript $candidate.File.FullName $fullRoot $DockerExecutable
            if ($exitCode -ne 0 -or -not (Test-Path -LiteralPath $childPath -PathType Leaf)) { Fail-Batch 'inspector_failed' }
            $result = Convert-ChildReportToEvidence $childPath $currentSha $candidate.File.Length $captureId
        }
        catch {
            $code = if ($_.Exception.Message -eq 'invalid_report_schema') { 'invalid_report_schema' } else { 'inspector_failed' }
            $result = Get-DefaultEvidence $captureId 'failed' $code
        }
        finally {
            if (Test-Path -LiteralPath $childPath -PathType Leaf) { Remove-Item -LiteralPath $childPath -Force -ErrorAction SilentlyContinue }
        }
        [void]$captures.Add($result)
        $updatedEntries = [System.Collections.ArrayList]@($updatedEntries | Where-Object { $_.internal_path -ne $candidate.Ordinal })
        [void]$updatedEntries.Add([ordered]@{
            internal_path = $candidate.Ordinal
            sha256 = $currentSha
            size_bytes = [int64]$candidate.File.Length
            last_result = $result.status
            capture_id = $captureId
            packet_count = $result.packet_count
            protocol_counts = $result.protocol_counts
            visibility = $result.visibility
            capability = $result.capability
            error_code = $result.error_code
        })
        Save-AtomicJson ([ordered]@{ schema_version = 2; state_id = $StateId; entries = @($updatedEntries) }) $privateStatePath
    }
    Save-AtomicJson ([ordered]@{ schema_version = 2; state_id = $StateId; entries = @($updatedEntries) }) $privateStatePath
    $succeeded = @($captures | Where-Object { $_.status -eq 'succeeded' }).Count
    $failed = @($captures | Where-Object { $_.status -eq 'failed' }).Count
    $skipped = @($captures | Where-Object { $_.status -eq 'skipped' }).Count
    $summary = [ordered]@{
        schema_version = 1
        batch_id = $BatchId
        selected_count = $captures.Count
        succeeded_count = $succeeded
        failed_count = $failed
        skipped_count = $skipped
        captures = @($captures)
    }
    $publicPath = [System.IO.Path]::Combine($outputPath, ('pcap-batch-' + $BatchId + '.json'))
    Assert-NoReparsePoints $publicPath 'output_reparse_point'
    Save-AtomicJson $summary $publicPath
    Write-Output ('pcap_batch_result={0}' -f $BatchId)
    exit 0
}
catch {
    $code = 'unexpected_failure'
    if ($script:PublicErrorCodes -contains $_.Exception.Message) { $code = $_.Exception.Message }
    Write-Output ('pcap_batch_error={0}' -f $code)
    exit 2
}
