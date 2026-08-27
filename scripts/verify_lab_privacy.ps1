[CmdletBinding()]
param(
    [string[]]$JsonPath = @(),
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
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
        "guard_raw_output"
    ),
    [System.StringComparer]::Ordinal
)
$forbiddenKeyPaths = [System.Collections.Generic.List[string]]::new()
$protectedTrackedPaths = [System.Collections.Generic.List[string]]::new()
$jsonErrors = [System.Collections.Generic.List[string]]::new()

function Find-ForbiddenKey {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string]$CurrentPath
    )

    if ($null -eq $Value) {
        return
    }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            $keyText = [string]$key
            $childPath = "$CurrentPath.$keyText"
            if ($forbiddenKeys.Contains($keyText)) {
                $forbiddenKeyPaths.Add($childPath)
            }
            Find-ForbiddenKey -Value $Value[$key] -CurrentPath $childPath
        }
        return
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $index = 0
        foreach ($item in $Value) {
            Find-ForbiddenKey -Value $item -CurrentPath "$CurrentPath[$index]"
            $index += 1
        }
    }
}

foreach ($path in $JsonPath) {
    try {
        $resolved = Resolve-Path -LiteralPath $path
        $payload = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8 |
            ConvertFrom-Json -AsHashtable -Depth 100
        Find-ForbiddenKey -Value $payload -CurrentPath '$'
    }
    catch {
        $jsonErrors.Add((Split-Path -Leaf $path))
    }
}

if (-not $SkipTrackedPathScan) {
    Push-Location -LiteralPath $RepositoryRoot
    try {
        $trackedPaths = @(git ls-files)
        if ($LASTEXITCODE -ne 0) {
            throw "git ls-files failed"
        }
        foreach ($trackedPath in $trackedPaths) {
            $normalized = $trackedPath.Replace('\', '/')
            $isProtected =
                $normalized -match '(^|/)\.secrets(/|$)' -or
                $normalized -match '(?i)\.(sqlite|sqlite3|db)(-|$)' -or
                $normalized -match '(?i)(^|/).*observation[-_]?cache.*$' -or
                $normalized -match '(?i)(^|/).*(source[-_]?prompts?|prompt[-_]?source).*\.jsonl$'
            if ($isProtected) {
                $protectedTrackedPaths.Add($normalized)
            }
        }
    }
    finally {
        Pop-Location
    }
}

foreach ($path in ($forbiddenKeyPaths | Sort-Object -Unique)) {
    Write-Output "forbidden-key:$path"
}
foreach ($path in ($protectedTrackedPaths | Sort-Object -Unique)) {
    Write-Output "tracked-path:$path"
}
foreach ($name in ($jsonErrors | Sort-Object -Unique)) {
    Write-Output "json-error:$name"
}

$failed = $forbiddenKeyPaths.Count -gt 0 -or
    $protectedTrackedPaths.Count -gt 0 -or
    $jsonErrors.Count -gt 0
$status = if ($failed) { "failed" } else { "passed" }
Write-Output (
    "privacy_verification={0} json_files={1} forbidden_key_hits={2} tracked_path_hits={3} json_errors={4}" -f
    $status,
    $JsonPath.Count,
    $forbiddenKeyPaths.Count,
    $protectedTrackedPaths.Count,
    $jsonErrors.Count
)

if ($failed) {
    exit 1
}
exit 0
