# BoltEdge EASM - Project Structure Scanner
# Run from the project root: .\show-structure.ps1
# Outputs a clean tree view of frontend and backend

param(
    [int]$Depth = 4,
    [switch]$Frontend,
    [switch]$Backend,
    [switch]$All
)

# If no flag specified, show all
if (-not $Frontend -and -not $Backend) { $All = $true }

$excludeDirs = @('node_modules', '.next', '__pycache__', 'venv', '.git', 'instance', 'Screnshoots', 'Screenshots')
$excludeFiles = @('.DS_Store', 'Thumbs.db', '*.pyc')

function Show-Tree {
    param(
        [string]$Path,
        [string]$Prefix = "",
        [int]$CurrentDepth = 0,
        [int]$MaxDepth = 4
    )

    if ($CurrentDepth -ge $MaxDepth) { return }

    $items = Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $name = $_.Name
            if ($_.PSIsContainer) {
                $name -notin $excludeDirs
            } else {
                $skip = $false
                foreach ($pattern in $excludeFiles) {
                    if ($name -like $pattern) { $skip = $true; break }
                }
                -not $skip
            }
        } |
        Sort-Object { -not $_.PSIsContainer }, Name

    for ($i = 0; $i -lt $items.Count; $i++) {
        $item = $items[$i]
        $isLast = ($i -eq $items.Count - 1)
        $connector = if ($isLast) { "`u{2514}`u{2500}`u{2500}" } else { "`u{251C}`u{2500}`u{2500}" }
        $extension = if ($isLast) { "    " } else { "`u{2502}   " }

        if ($item.PSIsContainer) {
            $fileCount = (Get-ChildItem -Path $item.FullName -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -notin @('.pyc') -and $_.Directory.Name -notin $excludeDirs }).Count
            Write-Host "${Prefix}${connector} " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($item.Name)/" -ForegroundColor Cyan -NoNewline
            Write-Host " ($fileCount files)" -ForegroundColor DarkGray
            Show-Tree -Path $item.FullName -Prefix "${Prefix}${extension}" -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth
        } else {
            $sizeKB = [math]::Round($item.Length / 1KB, 1)
            $color = switch -Wildcard ($item.Extension) {
                ".py"    { "Green" }
                ".tsx"   { "Yellow" }
                ".ts"    { "Yellow" }
                ".js"    { "Yellow" }
                ".json"  { "Magenta" }
                ".css"   { "Blue" }
                ".html"  { "Red" }
                ".yml"   { "DarkYellow" }
                ".yaml"  { "DarkYellow" }
                ".env*"  { "DarkRed" }
                ".md"    { "White" }
                ".txt"   { "White" }
                ".mjs"   { "Yellow" }
                ".sql"   { "DarkCyan" }
                default  { "Gray" }
            }
            Write-Host "${Prefix}${connector} " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($item.Name)" -ForegroundColor $color -NoNewline
            Write-Host " (${sizeKB}KB)" -ForegroundColor DarkGray
        }
    }
}

function Show-Summary {
    param([string]$Path, [string]$Label)

    $allFiles = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Directory.Name -notin $excludeDirs -and $_.Extension -ne '.pyc' }

    $extensions = $allFiles | Group-Object Extension | Sort-Object Count -Descending

    Write-Host ""
    Write-Host "  $Label File Summary:" -ForegroundColor White
    Write-Host "  $('-' * 40)" -ForegroundColor DarkGray
    Write-Host "  Total files: $($allFiles.Count)" -ForegroundColor White
    Write-Host "  Total size:  $([math]::Round(($allFiles | Measure-Object Length -Sum).Sum / 1KB, 1))KB" -ForegroundColor White
    Write-Host ""
    Write-Host "  By extension:" -ForegroundColor White
    foreach ($ext in $extensions | Select-Object -First 10) {
        $name = if ($ext.Name) { $ext.Name } else { "(no ext)" }
        Write-Host "    $($name.PadRight(10)) $($ext.Count) files" -ForegroundColor Gray
    }
}

# ── Header ──
Write-Host ""
Write-Host "  ================================================" -ForegroundColor DarkCyan
Write-Host "   BOLTEDGE EASM - Project Structure" -ForegroundColor Cyan
Write-Host "   Scanned: $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor DarkGray
Write-Host "  ================================================" -ForegroundColor DarkCyan
Write-Host ""

# ── Root files ──
Write-Host "  Root" -ForegroundColor White
$rootFiles = Get-ChildItem -Path . -File -Force | Where-Object { $_.Name -notin @('.DS_Store', 'Thumbs.db') } | Sort-Object Name
foreach ($f in $rootFiles) {
    Write-Host "  `u{251C}`u{2500}`u{2500} " -NoNewline -ForegroundColor DarkGray
    $color = switch -Wildcard ($f.Extension) {
        ".yml"  { "DarkYellow" }
        ".yaml" { "DarkYellow" }
        ".env*" { "DarkRed" }
        default { "Gray" }
    }
    Write-Host "$($f.Name)" -ForegroundColor $color
}
Write-Host ""

# ── Backend ──
if ($All -or $Backend) {
    if (Test-Path "./backend") {
        Write-Host "  `u{26A1} BACKEND (Flask/Python)" -ForegroundColor Green
        Write-Host "  $('=' * 40)" -ForegroundColor DarkGray
        Show-Tree -Path "./backend" -Prefix "  " -MaxDepth $Depth
        Show-Summary -Path "./backend" -Label "Backend"
        Write-Host ""
    } else {
        Write-Host "  [!] No backend/ directory found" -ForegroundColor Red
    }
}

# ── Frontend ──
if ($All -or $Frontend) {
    if (Test-Path "./frontend") {
        Write-Host ""
        Write-Host "  `u{26A1} FRONTEND (Next.js/TypeScript)" -ForegroundColor Yellow
        Write-Host "  $('=' * 40)" -ForegroundColor DarkGray
        Show-Tree -Path "./frontend" -Prefix "  " -MaxDepth $Depth
        Show-Summary -Path "./frontend" -Label "Frontend"
        Write-Host ""
    } else {
        Write-Host "  [!] No frontend/ directory found" -ForegroundColor Red
    }
}

Write-Host "  ================================================" -ForegroundColor DarkCyan
Write-Host "   Legend: " -NoNewline -ForegroundColor DarkGray
Write-Host ".py" -NoNewline -ForegroundColor Green
Write-Host " | " -NoNewline -ForegroundColor DarkGray
Write-Host ".tsx/.ts" -NoNewline -ForegroundColor Yellow
Write-Host " | " -NoNewline -ForegroundColor DarkGray
Write-Host ".json" -NoNewline -ForegroundColor Magenta
Write-Host " | " -NoNewline -ForegroundColor DarkGray
Write-Host ".css" -NoNewline -ForegroundColor Blue
Write-Host " | " -NoNewline -ForegroundColor DarkGray
Write-Host ".yml" -NoNewline -ForegroundColor DarkYellow
Write-Host " | " -NoNewline -ForegroundColor DarkGray
Write-Host ".env" -ForegroundColor DarkRed
Write-Host "  ================================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  Usage: .\show-structure.ps1 [-Depth 5] [-Frontend] [-Backend]" -ForegroundColor DarkGray
Write-Host ""