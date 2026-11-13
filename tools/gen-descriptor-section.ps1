param(
    [Parameter(Mandatory = $true)][string]$Cache,
    [Parameter(Mandatory = $true)][string]$Target,
    [string]$Rules = "app/src/main/assets/anchors/wechat.json",
    [string]$Descriptors = "app/src/main/assets/descriptors/wechat.json",
    [string]$DexSql = $env:DEXSQL,
    [string]$Out = "build/descriptors"
)
$ErrorActionPreference = "Stop"

# dexsql 定位与 verify-descriptor-table.ps1 保持一致
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

function Quote([string]$value) {
    return "'" + $value.Replace("'", "''") + "'"
}

# 与 DexKit usingStrings 一致：默认子串包含，% 与 _ 按字面量处理
function LikePattern([string]$value) {
    $escaped = $value.Replace("\", "\\").Replace("%", "\%").Replace("_", "\_").Replace("'", "''")
    return "'%" + $escaped + "%' ESCAPE '\'"
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

function To-Owner([string]$descriptor) {
    $value = $descriptor.Trim()
    if ($value.StartsWith("L") -and $value.EndsWith(";")) { $value = $value.Substring(1, $value.Length - 2) }
    return $value.Replace('/', '.')
}

function To-TypeName([string]$descriptor) {
    switch -CaseSensitive ($descriptor.Trim()) {
        "V" { return "void" }
        "Z" { return "boolean" }
        "I" { return "int" }
        "J" { return "long" }
        "S" { return "short" }
        "B" { return "byte" }
        "C" { return "char" }
        "F" { return "float" }
        "D" { return "double" }
        default {
            $value = $descriptor.Trim()
            if ($value.StartsWith("[")) { return (To-TypeName $value.Substring(1)) + "[]" }
            return (To-Owner $value)
        }
    }
}

# 解析 dexsql 的表格输出，按表头取列
function Read-Rows([string]$text) {
    $rows = @()
    $header = $null
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -notmatch '^\s*\|') { continue }
        $cells = @(($line.Trim().Trim('|') -split '\|') | ForEach-Object { $_.Trim() })
        if (-not $header) { $header = $cells; continue }
        $object = [ordered]@{}
        for ($i = 0; $i -lt $cells.Count -and $i -lt $header.Count; $i++) {
            $object[$header[$i]] = $cells[$i]
        }
        $rows += [pscustomobject]$object
    }
    return $rows
}

# 按规则的匹配条件构造查询：与 AnchorResolver.buildMatcher 的语义对应
# 字符串条件用 JOIN 而非相关子查询，空线索必须剔除，否则 LIKE '%%' 会扫全表
function Build-Sql($rule) {
    if ($rule.invokes -and @($rule.invokes).Count -gt 0) { return $null }
    $strings = @($rule.strings | Where-Object { $_ -and $_.Trim() })
    $classStrings = @($rule.classStrings | Where-Object { $_ -and $_.Trim() })
    if ($strings.Count -eq 0 -and $classStrings.Count -eq 0) { return $null }
    $joins = @()
    $where = @()
    if ($rule.returnType) { $where += ("m.return_descriptor = '" + (ConvertTo-ReturnDescriptor $rule.returnType) + "'") }
    if ($null -ne $rule.paramCount) { $where += ("m.param_count = " + [int]$rule.paramCount) }
    if ($rule.methodName) { $where += ("m.name = " + (Quote $rule.methodName)) }
    if ($rule.packagePrefix) { $where += ("m.class_descriptor LIKE " + (LikePattern ("L" + $rule.packagePrefix))) }
    if ($strings.Count -gt 0) {
        $joins += "JOIN method_strings s0 ON s0.method = m.descriptor"
        $conditions = @($strings | ForEach-Object {
            if ($rule.exactStrings) { "s0.value = " + (Quote $_) } else { "s0.value LIKE " + (LikePattern $_) }
        })
        $where += ("(" + ($conditions -join " OR ") + ")")
    }
    if ($classStrings.Count -gt 0) {
        $joins += "JOIN method_strings s1 ON s1.method_class = m.class_descriptor"
        $conditions = @($classStrings | ForEach-Object { "s1.value LIKE " + (LikePattern $_) })
        $where += ("(" + ($conditions -join " OR ") + ")")
    }
    return "SELECT DISTINCT m.class_descriptor AS c, m.name AS n, m.param_count AS p, m.return_descriptor AS r FROM methods m " + ($joins -join " ") + " WHERE " + ($where -join " AND ")
}

function To-Descriptor($row) {
    return ((To-Owner $row.c) + "#" + $row.n + "(" + $row.p + ")" + (To-TypeName $row.r))
}

if (-not (Test-Path $Rules)) { throw "缺少规则文件 $Rules" }
if (-not (Test-Path $Descriptors)) { throw "缺少描述符表 $Descriptors" }
$ruleSet = Get-Content $Rules -Raw | ConvertFrom-Json
$table = Get-Content $Descriptors -Raw | ConvertFrom-Json

$registered = @($table.versions.PSObject.Properties.Name | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
if ($registered.Count -eq 0) { throw "描述符表没有数字版本段" }
$targetValue = 0
if ($Target -match '^\d+$') { $targetValue = [int]$Target }
# 参照段必须排除目标自身，否则等于拿自己校验自己
$pools = @($registered | Where-Object { [string]$_ -ne $Target })
if ($pools.Count -eq 0) { $pools = $registered }
$reference = [string](($pools | Sort-Object { [math]::Abs($_ - $targetValue) })[0])
$known = @{}
if ($table.versions.PSObject.Properties.Name.Contains($reference)) {
    foreach ($prop in $table.versions.$reference.PSObject.Properties) { $known[$prop.Name] = @($prop.Value -split '\|')[0].Trim() }
}
Write-Output "== 目标 $Target，参照段 $reference（已登记 $($registered -join ' / ')）"

$section = [ordered]@{}
$report = @()
$script:total = @($ruleSet.rules).Count
$script:index = 0
$script:started = Get-Date
$script:progressPath = $env:GEN_PROGRESS_LOG
if (-not $script:progressPath) { $script:progressPath = "build/gen-progress.log" }
try {
    if (-not (Test-Path (Split-Path $script:progressPath -Parent))) { New-Item -ItemType Directory -Force (Split-Path $script:progressPath -Parent) | Out-Null }
    [IO.File]::WriteAllText($script:progressPath, "", [Text.UTF8Encoding]::new($false))
} catch { $script:progressPath = $null }

# 每条规则结束都落一行到进度文件，重定向缓冲下也能实时观察
function New-Result([string]$rule, [string]$status, [string]$value, [string]$detail) {
    $elapsed = [int]((Get-Date) - $script:started).TotalSeconds
    $line = "[" + $script:index + "/" + $script:total + "] " + $rule + " -> " + $status + " (" + $elapsed + "s)"
    Write-Output $line
    if ($script:progressPath) {
        [IO.File]::AppendAllText($script:progressPath, $line + "`r`n", [Text.UTF8Encoding]::new($false))
    }
    return [pscustomobject]@{ Rule = $rule; Status = $status; Value = $value; Detail = $detail }
}

foreach ($rule in $ruleSet.rules) {
    $script:index++
    $script:started = Get-Date
    $sql = Build-Sql $rule
    $old = if ($known.ContainsKey($rule.id)) { $known[$rule.id] } else { "" }
    if (-not $sql) {
        $detail = if ($rule.invokes -and @($rule.invokes).Count -gt 0) { "invokes 规则需人工定锚" } else { "无字符串线索，需人工定锚" }
        $report += New-Result $rule.id "UNSUPPORTED" $old $detail
        continue
    }
    $rows = @(Read-Rows (Invoke-DexSql $sql))
    $values = @($rows | ForEach-Object { To-Descriptor $_ } | Select-Object -Unique)
    if ($values.Count -eq 0) {
        $report += New-Result $rule.id "MISSING" $old "无线索命中"
        continue
    }
    if ($values.Count -eq 1) {
        $status = if ($old -and $old -eq $values[0]) { "SAME" } elseif ($old) { "CHANGED" } else { "NEW" }
        $detail = if ($old -and $old -ne $values[0]) { "参照值 $old 已失效" } else { "" }
        $report += New-Result $rule.id $status $values[0] $detail
        $section[$rule.id] = $values[0]
        continue
    }
    if ($old -and $values -contains $old) {
        $report += New-Result $rule.id "REUSED" $old ("候选 " + $values.Count + " 个，沿用参照值")
        $section[$rule.id] = $old
        continue
    }
    $detail = ($values | Select-Object -First 5) -join ' ; '
    $report += New-Result $rule.id "AMBIGUOUS" $old ("候选 " + $values.Count + " 个: " + $detail)
}

$summary = $report | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
Write-Output ("== 生成 " + $section.Count + " 条；" + ($summary -join ' '))
foreach ($item in ($report | Where-Object { $_.Status -in @("MISSING", "AMBIGUOUS", "UNSUPPORTED") })) {
    Write-Output ("   [" + $item.Status + "] " + $item.Rule + " " + $item.Detail)
}

if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Force $Out | Out-Null }
$payload = [ordered]@{
    section     = $Target
    reference   = $reference
    generatedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    descriptors = $section
    report      = $report
}
$json = $payload | ConvertTo-Json -Depth 6
$file = Join-Path $Out "$Target.section.json"
[IO.File]::WriteAllText($file, $json, (New-Object Text.UTF8Encoding($false)))
Write-Output "== 草案写入 $file"

# 同时输出可直接被 verify-descriptor-table.ps1 回放的最小表
$tablePayload = [ordered]@{ schemaVersion = 1; versions = [ordered]@{} }
$tablePayload.versions[$Target] = $section
$tableJson = $tablePayload | ConvertTo-Json -Depth 6
$tableFile = Join-Path $Out "$Target.table.json"
[IO.File]::WriteAllText($tableFile, $tableJson, (New-Object Text.UTF8Encoding($false)))
Write-Output "== 待回放表写入 $tableFile"

$unresolved = @($report | Where-Object { $_.Status -in @("MISSING", "AMBIGUOUS", "UNSUPPORTED") })
if ($unresolved.Count -gt 0) { exit 2 }
