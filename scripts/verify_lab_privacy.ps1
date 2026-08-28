[CmdletBinding()]
param(
    [string[]]$JsonPath = @(),
    [string[]]$DatabasePath = @(),
    [string]$BaseUrl = "",
    [string]$Sentinel = "",
    [string]$RepositoryRoot = "",
    [switch]$SkipTrackedPathScan
)

$ErrorActionPreference = "Stop"
$forbiddenKeys = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        "prompt",
        "suffix",
        "token_text",
        "token_id",
        "query_text",
        "raw_output",
        "guard_raw_output",
        "hidden_reasoning"
    ),
    [System.StringComparer]::Ordinal
)
$violations = @{}
$jsonErrors = 0
$protectedTrackedPaths = 0
$apiRequests = 0

function Add-PrivacyViolation {
    param(
        [Parameter(Mandatory = $true)][string]$Surface,
        [Parameter(Mandatory = $true)][string]$Category,
        [int]$Count = 1
    )

    if ($Count -le 0) {
        return
    }
    $key = "$Surface|$Category"
    if (-not $violations.ContainsKey($key)) {
        $violations[$key] = 0
    }
    $violations[$key] += $Count
}

function Find-PrivateJsonData {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string]$Surface,
        [string]$ExactSentinel = ""
    )

    if ($null -eq $Value) {
        return
    }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            $keyText = [string]$key
            if ($forbiddenKeys.Contains($keyText)) {
                Add-PrivacyViolation -Surface $Surface -Category "forbidden_key"
            }
            if (
                $ExactSentinel.Length -gt 0 -and
                $keyText.IndexOf(
                    $ExactSentinel, [System.StringComparison]::Ordinal
                ) -ge 0
            ) {
                Add-PrivacyViolation -Surface $Surface -Category "sentinel"
            }
            Find-PrivateJsonData -Value $Value[$key] -Surface $Surface -ExactSentinel $ExactSentinel
        }
        return
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        foreach ($property in $Value.PSObject.Properties) {
            if ($forbiddenKeys.Contains($property.Name)) {
                Add-PrivacyViolation -Surface $Surface -Category "forbidden_key"
            }
            if (
                $ExactSentinel.Length -gt 0 -and
                $property.Name.IndexOf(
                    $ExactSentinel, [System.StringComparison]::Ordinal
                ) -ge 0
            ) {
                Add-PrivacyViolation -Surface $Surface -Category "sentinel"
            }
            Find-PrivateJsonData `
                -Value $property.Value -Surface $Surface -ExactSentinel $ExactSentinel
        }
        return
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        foreach ($item in $Value) {
            Find-PrivateJsonData -Value $item -Surface $Surface -ExactSentinel $ExactSentinel
        }
        return
    }
    if (
        $ExactSentinel.Length -gt 0 -and
        $Value -is [string] -and
        $Value.IndexOf($ExactSentinel, [System.StringComparison]::Ordinal) -ge 0
    ) {
        Add-PrivacyViolation -Surface $Surface -Category "sentinel"
    }
}

function ConvertAndScan-JsonText {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Surface,
        [string]$ExactSentinel = ""
    )

    try {
        $payload = $Text | ConvertFrom-Json
        Find-PrivateJsonData -Value $payload -Surface $Surface -ExactSentinel $ExactSentinel
        return $payload
    }
    catch {
        Add-PrivacyViolation -Surface $Surface -Category "parse_error"
        $script:jsonErrors += 1
        return $null
    }
}

trap {
    Write-Output "surface=runtime category=unhandled_error count=1"
    Write-Output "privacy_verification=failed"
    exit 1
}

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
    $RepositoryRoot = (Resolve-Path (Join-Path $scriptDirectory "..")).Path
}

foreach ($path in $JsonPath) {
    try {
        $text = Get-Content -LiteralPath $path -Raw -Encoding UTF8
        $null = ConvertAndScan-JsonText `
            -Text $text -Surface "json" -ExactSentinel $Sentinel
    }
    catch {
        $jsonErrors += 1
        Add-PrivacyViolation -Surface "json" -Category "read_error"
    }
}

if (-not $SkipTrackedPathScan) {
    $locationPushed = $false
    try {
        Push-Location -LiteralPath $RepositoryRoot
        $locationPushed = $true
        $trackedPaths = @(git ls-files 2>$null)
        if ($LASTEXITCODE -ne 0) {
            Add-PrivacyViolation -Surface "repository" -Category "scan_error"
        }
        else {
            foreach ($trackedPath in $trackedPaths) {
                $normalized = $trackedPath.Replace('\', '/')
                $isProtected =
                    $normalized -match '(^|/)\.secrets(/|$)' -or
                    $normalized -match '(?i)\.(sqlite|sqlite3|db)(-|$)' -or
                    $normalized -match '(?i)(^|/).*observation[-_]?cache.*$' -or
                    $normalized -match '(?i)(^|/).*(source[-_]?prompts?|prompt[-_]?source).*\.jsonl$'
                if ($isProtected) {
                    $protectedTrackedPaths += 1
                }
            }
            Add-PrivacyViolation -Surface "repository" -Category "protected_path" -Count $protectedTrackedPaths
        }
    }
    catch {
        Add-PrivacyViolation -Surface "repository" -Category "read_error"
    }
    finally {
        if ($locationPushed) {
            Pop-Location
        }
    }
}

if ($DatabasePath.Count -gt 0) {
    $databaseScanner = @'
import json
import sqlite3
import sys
from pathlib import Path
from urllib.parse import quote

config = json.load(sys.stdin)
forbidden = set(config["forbidden"])
sentinel = config["sentinel"]
counts = {}

def add(surface, category, count=1):
    key = (surface, category)
    counts[key] = counts.get(key, 0) + count

def has_sentinel(value):
    return bool(sentinel) and sentinel in value

def quote_identifier(value):
    return '"' + value.replace('"', '""') + '"'

def scan_json(value, surface):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in forbidden:
                add(surface, "forbidden_key")
            if has_sentinel(key):
                add(surface, "sentinel")
            scan_json(child, surface)
    elif isinstance(value, list):
        for child in value:
            scan_json(child, surface)
    elif isinstance(value, str) and has_sentinel(value):
        add(surface, "sentinel")

for raw_path in config["paths"]:
    try:
        path = Path(raw_path).resolve(strict=True)
        uri_path = quote(str(path).replace("\\", "/"), safe="/:")
        connection = sqlite3.connect(f"file:{uri_path}?mode=ro", uri=True)
    except Exception:
        add("sqlite", "read_error")
        continue
    try:
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            if not row[0].startswith("sqlite_")
        ]
        surface = "sqlite"
        for table in tables:
            if table in forbidden:
                add(surface, "forbidden_table")
            if has_sentinel(table):
                add(surface, "sentinel")
            quoted_table = quote_identifier(table)
            columns = [
                row[1]
                for row in connection.execute(f"PRAGMA table_info({quoted_table})")
            ]
            for column in columns:
                if column in forbidden:
                    add(surface, "forbidden_column")
                if has_sentinel(column):
                    add(surface, "sentinel")
            for row in connection.execute(f"SELECT * FROM {quoted_table}"):
                for index, cell in enumerate(row):
                    if cell is None:
                        continue
                    if isinstance(cell, bytes):
                        try:
                            text = cell.decode("utf-8")
                        except UnicodeDecodeError:
                            add(surface, "opaque_blob")
                            if sentinel and sentinel.encode("utf-8") in cell:
                                add(surface, "sentinel")
                            continue
                        try:
                            parsed = json.loads(text)
                        except (json.JSONDecodeError, TypeError):
                            add(surface, "parse_error")
                            if has_sentinel(text):
                                add(surface, "sentinel")
                            continue
                        scan_json(parsed, surface)
                        continue
                    elif isinstance(cell, str):
                        text = cell
                    else:
                        text = str(cell)
                    try:
                        parsed = json.loads(text)
                    except (json.JSONDecodeError, TypeError):
                        if has_sentinel(text):
                            add(surface, "sentinel")
                        continue
                    scan_json(parsed, surface)
    except Exception:
        add("sqlite", "scan_error")
    finally:
        connection.close()

print(json.dumps([
    {"surface": surface, "category": category, "count": count}
    for (surface, category), count in sorted(counts.items())
], separators=(",", ":")))
'@
    try {
        $pythonCommand = Get-Command python -ErrorAction Stop
        $databaseConfig = @{
            paths = @($DatabasePath)
            forbidden = @($forbiddenKeys | Sort-Object)
            sentinel = $Sentinel
        } | ConvertTo-Json -Compress
        $encodedScanner = [Convert]::ToBase64String(
            [System.Text.Encoding]::UTF8.GetBytes($databaseScanner)
        )
        $databaseOutput = $databaseConfig | & $pythonCommand.Source `
            -c "import base64,sys;exec(base64.b64decode(sys.argv[1]))" `
            $encodedScanner 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "database scanner failed"
        }
        $databaseFindings = $databaseOutput | ConvertFrom-Json
        foreach ($finding in $databaseFindings) {
            $findingCount = [int]$finding.count
            Add-PrivacyViolation `
                -Surface ([string]$finding.surface) `
                -Category ([string]$finding.category) `
                -Count $findingCount
            if ($finding.category -in @("parse_error", "opaque_blob")) {
                $jsonErrors += $findingCount
            }
        }
    }
    catch {
        Add-PrivacyViolation -Surface "sqlite" -Category "scan_error"
    }
}

function Invoke-PrivacyHttp {
    param(
        [Parameter(Mandatory = $true)][System.Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][object]$Body
    )

    $script:apiRequests += 1
    try {
        $request = [System.Net.Http.HttpRequestMessage]::new(
            [System.Net.Http.HttpMethod]::new($Method),
            $BaseUrl.TrimEnd('/') + $Path
        )
        if ($null -ne $Body) {
            $json = $Body | ConvertTo-Json -Compress -Depth 20
            $request.Content = [System.Net.Http.StringContent]::new(
                $json,
                [System.Text.Encoding]::UTF8,
                "application/json"
            )
        }
        try {
            $response = $Client.SendAsync($request).GetAwaiter().GetResult()
            $bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            return [pscustomobject]@{
                StatusCode = [int]$response.StatusCode
                Body = $bytes
            }
        }
        finally {
            $request.Dispose()
            if ($null -ne $response) {
                $response.Dispose()
            }
        }
    }
    catch {
        return $null
    }
}

function Get-PrivacyProperty {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [System.Collections.IDictionary]) {
        return $Value[$Name]
    }
    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-PrivacyViolationCount {
    param([Parameter(Mandatory = $true)][string]$Surface)

    $count = 0
    foreach ($key in $violations.Keys) {
        if ($key.StartsWith("$Surface|", [System.StringComparison]::Ordinal)) {
            $count += $violations[$key]
        }
    }
    return $count
}

function Invoke-AndScanApiJson {
    param(
        [Parameter(Mandatory = $true)][System.Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Surface,
        [Parameter(Mandatory = $true)][int[]]$ExpectedStatus,
        [AllowNull()][object]$Body,
        [string]$ExactSentinel = ""
    )

    $result = Invoke-PrivacyHttp -Client $Client -Method $Method -Path $Path -Body $Body
    if ($null -eq $result) {
        Add-PrivacyViolation -Surface $Surface -Category "transport_error"
        return $null
    }
    if ($result.StatusCode -notin $ExpectedStatus) {
        Add-PrivacyViolation -Surface $Surface -Category "http_status"
    }
    try {
        $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($result.Body)
    }
    catch {
        Add-PrivacyViolation -Surface $Surface -Category "parse_error"
        $script:jsonErrors += 1
        return $null
    }
    $payload = ConvertAndScan-JsonText `
        -Text $text -Surface $Surface -ExactSentinel $ExactSentinel
    return [pscustomobject]@{
        StatusCode = $result.StatusCode
        Payload = $payload
    }
}

if ($BaseUrl.Length -gt 0) {
    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromMinutes(10)
    try {
        $apiSentinel = if ($Sentinel.Length -gt 0) {
            $Sentinel
        }
        else {
            "TASK9_PRIVATE_SENTINEL_" + [guid]::NewGuid().ToString("N")
        }
        $healthResult = Invoke-AndScanApiJson `
            -Client $client -Method "GET" -Path "/health" `
            -Surface "api.health" -ExpectedStatus @(200) -ExactSentinel $apiSentinel
        $health = if ($null -eq $healthResult) { $null } else { $healthResult.Payload }
        $labHealth = Get-PrivacyProperty -Value $health -Name "lab"
        $supportsExecution =
            $null -ne $healthResult -and
            $healthResult.StatusCode -eq 200 -and
            (Get-PrivacyViolationCount -Surface "api.health") -eq 0 -and
            (Get-PrivacyProperty -Value $labHealth -Name "ready") -eq $true -and
            (Get-PrivacyProperty -Value $labHealth -Name "tool_storage") -eq "sqlite"
        if (-not $supportsExecution) {
            Add-PrivacyViolation -Surface "api.health" -Category "unsupported"
        }
        else {
            $null = Invoke-AndScanApiJson `
                -Client $client -Method "GET" -Path "/api/v1/lab/scenarios" `
                -Surface "api.scenarios" -ExpectedStatus @(200) -ExactSentinel $apiSentinel
            $createdResult = Invoke-AndScanApiJson `
                -Client $client -Method "POST" -Path "/api/v1/lab/runs" `
                -Surface "api.create_run" -ExpectedStatus @(201) `
                -Body @{scenario_kind="custom"; custom_input=$apiSentinel; mode="analysis"} `
                -ExactSentinel $apiSentinel
            $created = if ($null -eq $createdResult) { $null } else { $createdResult.Payload }
            $runId = [string](Get-PrivacyProperty -Value $created -Name "run_id")
            if ($runId.Length -eq 0) {
                Add-PrivacyViolation -Surface "api.create_run" -Category "contract_error"
            }
            else {
                $encodedRunId = [uri]::EscapeDataString($runId)
                $runSurfaceSpecs = @(
                    [pscustomobject]@{
                        Phase="before_execute"; Method="GET"
                        Path="/api/v1/lab/runs/$encodedRunId"
                        Surface="api.get_run"; ExpectedStatus=@(200); Body=$null
                    },
                    [pscustomobject]@{
                        Phase="before_execute"; Method="POST"
                        Path="/api/v1/lab/runs/$encodedRunId/tools/gateway_enforcement/dry-run"
                        Surface="api.dry_run"; ExpectedStatus=@(200)
                        Body=@{inject_failure=$false}
                    },
                    [pscustomobject]@{
                        Phase="after_execute"; Method="GET"
                        Path="/api/v1/lab/runs/$encodedRunId/executions"
                        Surface="api.list"; ExpectedStatus=@(200); Body=$null
                    },
                    [pscustomobject]@{
                        Phase="after_artifact"; Method="POST"
                        Path="/api/v1/lab/runs/$encodedRunId/tools/security_case/execute"
                        Surface="api.validation_422"; ExpectedStatus=@(422)
                        Body=@{
                            confirmed=$false
                            idempotency_key="not-a-uuid"
                            hidden_reasoning=$apiSentinel
                        }
                    }
                )
                foreach ($spec in $runSurfaceSpecs) {
                    if ($spec.Phase -ne "before_execute") {
                        continue
                    }
                    $null = Invoke-AndScanApiJson `
                        -Client $client -Method $spec.Method -Path $spec.Path `
                        -Surface $spec.Surface -ExpectedStatus $spec.ExpectedStatus `
                        -Body $spec.Body -ExactSentinel $apiSentinel
                }
                $executedResult = Invoke-AndScanApiJson `
                    -Client $client -Method "POST" `
                    -Path "/api/v1/lab/runs/$encodedRunId/tools/evidence_bundle/execute" `
                    -Surface "api.execute" -ExpectedStatus @(200, 201) `
                    -Body @{confirmed=$true; idempotency_key=[guid]::NewGuid().ToString()} `
                    -ExactSentinel $apiSentinel
                $executed = if ($null -eq $executedResult) { $null } else { $executedResult.Payload }
                foreach ($spec in $runSurfaceSpecs) {
                    if ($spec.Phase -ne "after_execute") {
                        continue
                    }
                    $null = Invoke-AndScanApiJson `
                        -Client $client -Method $spec.Method -Path $spec.Path `
                        -Surface $spec.Surface -ExpectedStatus $spec.ExpectedStatus `
                        -Body $spec.Body -ExactSentinel $apiSentinel
                }
                $artifactId = [string](Get-PrivacyProperty -Value $executed -Name "artifact_id")
                if ($artifactId.Length -eq 0) {
                    Add-PrivacyViolation -Surface "api.artifact" -Category "contract_error"
                }
                else {
                    $artifact = Invoke-PrivacyHttp `
                        -Client $client -Method "GET" `
                        -Path ("/api/v1/lab/artifacts/" + [uri]::EscapeDataString($artifactId) + "/download") `
                        -Body $null
                    if ($null -eq $artifact) {
                        Add-PrivacyViolation -Surface "api.artifact" -Category "transport_error"
                    }
                    else {
                        if ($artifact.StatusCode -ne 200) {
                            Add-PrivacyViolation -Surface "api.artifact" -Category "http_status"
                        }
                        try {
                            $artifactText = [System.Text.UTF8Encoding]::new($false, $true).GetString($artifact.Body)
                            $null = ConvertAndScan-JsonText `
                                -Text $artifactText -Surface "api.artifact" -ExactSentinel $apiSentinel
                        }
                        catch {
                            Add-PrivacyViolation -Surface "api.artifact" -Category "opaque_blob"
                            $jsonErrors += 1
                        }
                    }
                }
                foreach ($spec in $runSurfaceSpecs) {
                    if ($spec.Phase -ne "after_artifact") {
                        continue
                    }
                    $null = Invoke-AndScanApiJson `
                        -Client $client -Method $spec.Method -Path $spec.Path `
                        -Surface $spec.Surface -ExpectedStatus $spec.ExpectedStatus `
                        -Body $spec.Body -ExactSentinel $apiSentinel
                }
            }
        }
    }
    finally {
        $client.Dispose()
    }
}

$forbiddenKeyHits = 0
$sqliteViolations = 0
$apiViolations = 0
foreach ($key in $violations.Keys) {
    $parts = $key.Split('|', 2)
    if ($parts[1] -eq "forbidden_key") {
        $forbiddenKeyHits += $violations[$key]
    }
    if ($parts[0].StartsWith("sqlite", [System.StringComparison]::Ordinal)) {
        $sqliteViolations += $violations[$key]
    }
    if ($parts[0].StartsWith("api.", [System.StringComparison]::Ordinal)) {
        $apiViolations += $violations[$key]
    }
}

foreach ($key in ($violations.Keys | Sort-Object)) {
    $parts = $key.Split('|', 2)
    Write-Output (
        "surface={0} category={1} count={2}" -f
        $parts[0], $parts[1], $violations[$key]
    )
}

$failed = $violations.Count -gt 0
$status = if ($failed) { "failed" } else { "passed" }
Write-Output (
    ("privacy_verification={0} json_files={1} forbidden_key_hits={2} " +
    "tracked_path_hits={3} json_errors={4} sqlite_databases={5} " +
    "sqlite_violations={6} api_requests={7} api_violations={8}") -f
    $status,
    $JsonPath.Count,
    $forbiddenKeyHits,
    $protectedTrackedPaths,
    $jsonErrors,
    $DatabasePath.Count,
    $sqliteViolations,
    $apiRequests,
    $apiViolations
)

if ($failed) {
    exit 1
}
exit 0
