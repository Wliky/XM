param(
    [Parameter(Mandatory = $true)][string]$Cache,
    [Parameter(Mandatory = $true)][string]$VersionKey,
    [string]$DexSql = $env:DEXSQL,
    [string]$Descriptors = "app/src/main/assets/descriptors/wechat.json",
    [string]$Probe = $env:ALLOW_FALLBACK
)
$ErrorActionPreference = "Stop"
$exe = $DexSql
if (-not $exe -or -not (Test-Path $exe)) {
    foreach ($candidate in @(
        "C:/Develop/Github/Tools/dexsql-windows-amd64.exe",
        "C:/Develop/Github/X/.codebuddy/reverse/tools/dexsql.exe"
    )) {
        if (Test-Path $candidate) { $exe = $candidate; break }
    }
}
if (-not $exe -or -not (Test-Path $exe)) {
    $command = Get-Command dexsql -ErrorAction SilentlyContinue
    if ($command) { $exe = $command.Source }
}
if (-not $exe -or -not (Test-Path $exe)) { throw "找不到 dexsql，可用 -DexSql 或 DEXSQL 环境变量指定路径" }

function Invoke-DexSql([string]$sql) {
    $raw = & $exe query-cache --cache-file $Cache --sql $sql 2>&1
    if ($LASTEXITCODE -ne 0) { throw ("SQL failed: " + ($raw -join " ") + " | " + $sql) }
    return ($raw | Out-String)
}

function ConvertTo-ClassDescriptor([string]$owner) {
    if ($owner.StartsWith("L") -and $owner.EndsWith(";")) { return $owner }
    return "L" + $owner.Replace('.', '/') + ";"
}

function ConvertTo-ReturnDescriptor([string]$type) {
    switch ($type) {
        "void" { return "V" }
        "boolean" { return "Z" }
        "int" { return "I" }
        "long" { return "J" }
        "short" { return "S" }
        "byte" { return "B" }
        "char" { return "C" }
        "float" { return "F" }
        "double" { return "D" }
        default {
            if ($type.EndsWith("[]")) { return "[" + (ConvertTo-ReturnDescriptor $type.Substring(0, $type.Length - 2)) }
            return "L" + $type.Replace('.', '/') + ";"
        }
    }
}

function Get-TypeEnd([string]$spec, [int]$start) {
    if ($start -ge $spec.Length) { return -1 }
    if ($spec[$start] -eq '[') {
        $index = $start
        while ($index -lt $spec.Length -and $spec[$index] -eq '[') { $index++ }
        if ($index -ge $spec.Length) { return -1 }
        return (Get-TypeEnd $spec $index)
    }
    switch -CaseSensitive ([string]$spec[$start]) {
        'L' {
            $semicolon = $spec.IndexOf(';', $start)
            if ($semicolon -lt 0) { return -1 }
            return $semicolon + 1
        }
        'Z' { return $start + 1 }
        'B' { return $start + 1 }
        'C' { return $start + 1 }
        'S' { return $start + 1 }
        'I' { return $start + 1 }
        'J' { return $start + 1 }
        'F' { return $start + 1 }
        'D' { return $start + 1 }
        default { return -1 }
    }
}

function Split-ParamTypes([string]$spec) {
    if ([string]::IsNullOrEmpty($spec)) { return $null }
    $types = New-Object System.Collections.ArrayList
    $index = 0
    while ($index -lt $spec.Length) {
        $end = Get-TypeEnd $spec $index
        if ($end -le $index) { return $null }
        [void]$types.Add($spec.Substring($index, $end - $index))
        $index = $end
    }
    return $types.ToArray()
}

function Read-MethodRows([string]$classDesc, [string]$name, [string]$retDesc) {
    $text = Invoke-DexSql "SELECT DISTINCT param_descriptors, param_count FROM methods WHERE class_descriptor = '$classDesc' AND name = '$name' AND return_descriptor = '$retDesc'"
    $rows = @()
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '^\|\s*([^|]*?)\s*\|\s*(\d+)\s*\|') {
            $rows += [pscustomobject]@{ Params = $Matches[1]; ParamCount = [int]$Matches[2] }
        }
    }
    return $rows
}

if (-not (Test-Path $Descriptors)) { throw "缺少描述符表 $Descriptors" }
$table = Get-Content $Descriptors -Raw | ConvertFrom-Json
$available = @($table.versions.PSObject.Properties.Name) -join ' / '
$probeFrom = $null
if (-not $table.versions.PSObject.Properties.Name.Contains($VersionKey)) {
    # 目标版本没登记时可选试探：拿最近的已登记段跑一遍，失败条目就是该补的锚点。
    if ($Probe -ne 'true') {
        throw "descriptor table has no section $VersionKey（已登记：$available），要试探回放请设 ALLOW_FALLBACK=true"
    }
    $keys = @($table.versions.PSObject.Properties.Name | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
    if ($keys.Count -eq 0) { throw "descriptor table has no numeric section（已登记：$available）" }
    $target = 0
    if ($VersionKey -match '^\d+$') { $target = [int]$VersionKey }
    # 取距离最近的已登记段：相邻版本混淆布局更接近，回放命中率才高。
    $probeFrom = [string](($keys | Sort-Object { [math]::Abs($_ - $target) })[0])
    Write-Output "== section $VersionKey 未登记，改用最近的 $probeFrom 试探回放"
}
$sectionKey = if ($probeFrom) { $probeFrom } else { $VersionKey }
$section = $table.versions.$sectionKey

$rows = @()
foreach ($prop in $section.PSObject.Properties) {
    foreach ($descriptor in ($prop.Value -split '\|')) {
        $value = $descriptor.Trim()
        if (-not $value) { continue }
        if ($value -notmatch '^(?<owner>[^#]+)#(?<name>[^\(]+)\((?<spec>[^\)]*)\)(?<ret>.+)$') {
            $rows += [pscustomobject]@{ Rule = $prop.Name; Descriptor = $value; Status = "BAD-FORMAT"; Detail = "" }
            continue
        }
        $owner = $Matches.owner
        $name = $Matches.name
        $spec = $Matches.spec
        $ret = $Matches.ret
        $counted = $spec -match '^\d+$'
        $types = $null
        if (-not $counted) {
            $types = Split-ParamTypes $spec
            if (-not $types) {
                $rows += [pscustomobject]@{ Rule = $prop.Name; Descriptor = $value; Status = "BAD-FORMAT"; Detail = "param types: $spec" }
                continue
            }
        }
        $classDesc = ConvertTo-ClassDescriptor $owner
        $retDesc = ConvertTo-ReturnDescriptor $ret

        $classText = Invoke-DexSql "SELECT count(*) AS n FROM classes WHERE descriptor = '$classDesc'"
        if ($classText -match '\|\s*0\s*\|') {
            $rows += [pscustomobject]@{ Rule = $prop.Name; Descriptor = $value; Status = "NO-CLASS"; Detail = $classDesc }
            continue
        }

        $candidates = @(Read-MethodRows $classDesc $name $retDesc)
        if ($candidates.Count -eq 0) {
            $rows += [pscustomobject]@{ Rule = $prop.Name; Descriptor = $value; Status = "NO-METHOD"; Detail = "$classDesc $name $retDesc" }
            continue
        }

        if (-not $counted) {
            $wanted = ($types -join ',')
            $hit = @($candidates | Where-Object { $_.Params -eq $wanted })
            if ($hit.Count -eq 1) {
                $rows += [pscustomobject]@{ Rule = $prop.Name; Descriptor = $value; Status = "EXACT"; Detail = "" }
            } elseif ($hit.Count -gt 1) {
                $rows += [pscustomobject]@{ Rule = $prop.Name; Descriptor = $value; Status = "AMBIGUOUS"; Detail = $wanted }
            } else {
                $actual = ($candidates | ForEach-Object { "$($_.ParamCount)($($_.Params))" }) -join ' | '
                $rows += [pscustomobject]@{ Rule = $prop.Name; Descriptor = $value; Status = "NO-METHOD"; Detail = "actual $actual" }
            }
            continue
        }

        $count = [int]$spec
        $minDistance = ($candidates | ForEach-Object { [math]::Abs($_.ParamCount - $count) } | Measure-Object -Minimum).Minimum
        $nearest = @($candidates | Where-Object { [math]::Abs($_.ParamCount - $count) -eq $minDistance })
        if ($nearest.Count -gt 1) {
            $picked = ($nearest | ForEach-Object { "$($_.ParamCount)($($_.Params))" }) -join ' | '
            $rows += [pscustomobject]@{ Rule = $prop.Name; Descriptor = $value; Status = "AMBIGUOUS"; Detail = $picked }
            continue
        }
        if ($minDistance -eq 0) {
            $rows += [pscustomobject]@{ Rule = $prop.Name; Descriptor = $value; Status = "EXACT"; Detail = "" }
        } else {
            $rows += [pscustomobject]@{ Rule = $prop.Name; Descriptor = $value; Status = "RELOCATED"; Detail = "actual param count=$($nearest[0].ParamCount)" }
        }
    }
}

Write-Output ("== section $sectionKey entries: " + $rows.Count)
$rows | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Output

$verdicts = @()
foreach ($group in ($rows | Group-Object Rule)) {
    $statuses = @($group.Group | ForEach-Object { $_.Status })
    if ($statuses -contains "EXACT") {
        $verdicts += [pscustomobject]@{ Rule = $group.Name; Verdict = "PASS"; Detail = "" }
    } elseif ($statuses -contains "RELOCATED") {
        $verdicts += [pscustomobject]@{ Rule = $group.Name; Verdict = "WARN"; Detail = "只命中重定位" }
    } else {
        $detail = (@($group.Group | ForEach-Object { "$($_.Status):$($_.Detail)" }) -join ' ; ')
        $verdicts += [pscustomobject]@{ Rule = $group.Name; Verdict = "FAIL"; Detail = $detail }
    }
}

$failed = @($verdicts | Where-Object { $_.Verdict -eq "FAIL" })
$warned = @($verdicts | Where-Object { $_.Verdict -eq "WARN" })
Write-Output ("== rules: " + $verdicts.Count + " pass=" + ($verdicts.Count - $failed.Count - $warned.Count) + " warn=" + $warned.Count + " fail=" + $failed.Count)
if ($warned.Count -gt 0) {
    $warned | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Output
}
if ($failed.Count -gt 0) {
    $failed | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Output
}
Write-Output ("failed=" + $failed.Count)
if ($probeFrom) {
    if ($failed.Count -eq 0) {
        Write-Output "== $VersionKey 与 $probeFrom 结构一致：把 $probeFrom 段复制成 $VersionKey 段即可"
    } else {
        Write-Output "== $VersionKey 相对 $probeFrom 有 $($failed.Count) 条需要重新定锚：$((@($failed | ForEach-Object { $_.Rule })) -join ', ')"
    }
}
if ($failed.Count -gt 0) { exit 1 }
