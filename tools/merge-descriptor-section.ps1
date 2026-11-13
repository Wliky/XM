<#
.SYNOPSIS
把探测阶段生成的描述符草案合并进正式描述符表。

.DESCRIPTION
只合并已定锚的条目（SAME / NEW / CHANGED / REUSED），未定锚状态
（MISSING / AMBIGUOUS / UNSUPPORTED）一律跳过，避免把猜测写进正式表。
默认演练不落盘，加 -Apply 才写文件。

.PARAMETER Descriptors
正式描述符表，如 app/src/main/assets/descriptors/wechat.json

.PARAMETER Draft
草案文件，可以是 <version>.section.json 或 <version>.table.json

.PARAMETER Section
目标版本段，留空则从草案推断

.PARAMETER AllowOverwrite
允许覆盖段内已存在且取值不同的条目
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Descriptors,
    [Parameter(Mandatory = $true)][string]$Draft,
    [string]$Section = "",
    [switch]$Apply,
    [switch]$AllowOverwrite
)

$ErrorActionPreference = 'Stop'

$allowed = @('SAME', 'NEW', 'CHANGED', 'REUSED')

function Read-Json([string]$path) {
    if (-not (Test-Path $path)) { throw "文件不存在: $path" }
    $text = [IO.File]::ReadAllText((Resolve-Path $path).Path, [Text.Encoding]::UTF8)
    return ($text | ConvertFrom-Json)
}

function Has-Prop($obj, [string]$name) {
    if ($null -eq $obj) { return $false }
    return ($obj.PSObject.Properties.Name -contains $name)
}

$table = Read-Json $Descriptors
# PowerShell 变量名不区分大小写，这里不能复用参数名 $Draft
$doc = Read-Json $Draft

$sectionKey = $Section
$entries = $null
$report = $null

if (Has-Prop $doc 'versions') {
    $keys = @($doc.versions.PSObject.Properties.Name)
    if ($keys.Count -ne 1) { throw "草案表必须只含一个版本段，实际: $($keys -join ',')" }
    if (-not $sectionKey) { $sectionKey = [string]$keys[0] }
    if ($sectionKey -ne [string]$keys[0]) { throw "指定段 $sectionKey 与草案段 $($keys[0]) 不一致" }
    $entries = $doc.versions.$($keys[0])
} elseif (Has-Prop $doc 'descriptors') {
    if (-not $sectionKey) { $sectionKey = [string]$doc.section }
    $entries = $doc.descriptors
    $report = $doc.report
} else {
    throw "草案既没有 versions 也没有 descriptors: $Draft"
}

if ($null -eq $entries) { throw "草案里没有可合并的条目" }
if (-not $sectionKey) { throw "无法确定目标版本段，请用 -Section 指定" }

$blocked = @{}
if ($null -ne $report) {
    foreach ($item in $report) {
        $status = [string]$item.Status
        if ($allowed -notcontains $status) { $blocked[[string]$item.Rule] = $status }
    }
}

$existing = $null
if (Has-Prop $table.versions $sectionKey) { $existing = $table.versions.$sectionKey }
if ($null -eq $existing) { $existing = New-Object psobject }

$added = @()
$updated = @()
$skipped = @()

foreach ($prop in $entries.PSObject.Properties) {
    $id = [string]$prop.Name
    $value = [string]$prop.Value
    if ($blocked.ContainsKey($id)) { $skipped += "$id(未定锚 $($blocked[$id]))"; continue }
    if (-not $value) { $skipped += "$id(空值)"; continue }
    if (Has-Prop $existing $id) {
        $old = [string]$existing.$id
        if ($old -eq $value) { continue }
        if (-not $AllowOverwrite) { $skipped += "$id(已有 $old)"; continue }
        $existing.$id = $value
        $updated += "$id $old -> $value"
    } else {
        $existing | Add-Member -NotePropertyName $id -NotePropertyValue $value
        $added += "$id $value"
    }
}

Write-Output ("== 段 " + $sectionKey + "：新增 " + $added.Count + "，更新 " + $updated.Count + "，跳过 " + $skipped.Count)
foreach ($line in $added) { Write-Output ("   + " + $line) }
foreach ($line in $updated) { Write-Output ("   ~ " + $line) }
foreach ($line in $skipped) { Write-Output ("   - " + $line) }

if (-not $Apply) {
    Write-Output "== 演练模式，未写文件（加 -Apply 落盘）"
    exit 0
}

if (($added.Count + $updated.Count) -eq 0) {
    Write-Output "== 没有需要写入的条目"
    exit 0
}

if (-not (Has-Prop $table.versions $sectionKey)) {
    $table.versions | Add-Member -NotePropertyName $sectionKey -NotePropertyValue $existing
}

$json = $table | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText((Resolve-Path $Descriptors).Path, $json + "`n", (New-Object Text.UTF8Encoding($false)))
Write-Output "== 已写入 $Descriptors"
