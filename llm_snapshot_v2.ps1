param(
    [string]$ProjectFolder,
    [int]$MaxFileMB = 5,
    [switch]$RedactSecrets,
    [string[]]$Include,
    [string[]]$Exclude,
    [switch]$IncludeManifests = $true,
    [switch]$Zip = $true,
    [switch]$SkipGit,
    [int]$GitLastN = 400,
    [int]$LargestFilesTopN = 40,
    [string]$OutputDir,
    [switch]$EmitMetadataJson  # NEW
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info($msg){ Write-Host "• $msg" -ForegroundColor Cyan }
function Write-Warn($msg){ Write-Host "! $msg" -ForegroundColor Yellow }
function Write-Err ($msg){ Write-Host "✖ $msg" -ForegroundColor Red }

if (-not $ProjectFolder -or -not (Test-Path $ProjectFolder -PathType Container)) {
    do {
        $ProjectFolder = Read-Host "Enter the full path to your project folder"
        if (-not (Test-Path $ProjectFolder -PathType Container)) {
            Write-Err "'$ProjectFolder' is not a valid directory."
        }
    } until (Test-Path $ProjectFolder -PathType Container)
}

$Root = (Resolve-Path $ProjectFolder).Path
$depth = ($Root -split '[\\/]').Where({ $_ -ne '' }).Count
if ($depth -lt 3) {
    Write-Warn "This directory looks very high-level: $Root"
    $continue = Read-Host "Are you sure you want to continue? (y/n)"
    if ($continue -ne 'y') { Write-Err "Aborting for safety."; exit 1 }
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $OutputDir) {
    $OutputDir = Join-Path (Split-Path $Root -Parent) "llm_snapshot_$timestamp"
}
if (Test-Path $OutputDir) { Remove-Item -Recurse -Force $OutputDir }
New-Item -ItemType Directory -Path $OutputDir | Out-Null

$MonoFile   = Join-Path $OutputDir "llm_inference_knowledge_$timestamp.txt"
$TreeFile   = Join-Path $OutputDir "llm_directory_tree_$timestamp.txt"
$GitLogFile = Join-Path $OutputDir "llm_git_commit_messages_$timestamp.txt"
$Summary    = Join-Path $OutputDir "llm_summary_$timestamp.txt"
$SnapshotReadme = Join-Path $OutputDir "README_SNAPSHOT.md"
$MetaJson   = Join-Path $OutputDir "snapshot_meta.json"

$DefaultExcludedDirs = @(
  'node_modules','.next','.turbo','dist','build','out','public','__pycache__','.venv','venv',
  '.mypy_cache','.pytest_cache','bin','pkg','target','.gradle','.idea','.vs','obj','.vscode',
  '.cache','.vercel','.terraform','.git','coverage'
)
$DefaultExcludedExts = @(
  '.png','.jpg','.jpeg','.gif','.webp','.ico','.svg',
  '.exe','.dll','.zip','.7z','.tar','.gz','.rar',
  '.mp4','.mov','.avi','.mkv','.wav','.mp3','.flac',
  '.pyc','.class','.o','.so','.a','.dylib',
  '.pdf','.docx','.pptx','.xlsx'
)
$DefaultExcludedFiles = @(
  'package-lock.json','yarn.lock','pnpm-lock.yaml','Cargo.lock','go.sum',
  '.classpath','.project','.settings','.DS_Store','Thumbs.db','.editorconfig','.coverage',
  '.envrc','.env','.env.local','.env.production','.env.development','.env.test'
)

$ManifestKeep = @(
  'package.json','pyproject.toml','requirements.txt','Pipfile','Pipfile.lock',
  'setup.py','poetry.lock','go.mod','go.work','Cargo.toml',
  'CMakeLists.txt','Makefile','build.gradle','pom.xml','Gemfile','composer.json'
)

$UserExclude = $Exclude

function RelPath([string]$full){ return $full.Substring($Root.Length).TrimStart('\','/') }

function IsLikelyBinary([string]$path) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        if ($bytes.Length -eq 0) { return $false }
        if ($bytes.Length -ge 2 -and (
            ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) -or
            ($bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF))) { return $false }
        $nonText = 0; $sample = [Math]::Min($bytes.Length, 8000)
        for ($i=0; $i -lt $sample; $i++){
            $b = $bytes[$i]
            if (($b -eq 0) -or ($b -lt 9) -or (($b -ge 14) -and ($b -le 31))) { $nonText++ }
        }
        return ($nonText / $sample) -gt 0.30
    } catch {
        # If we can't read it, assume text so we don't over-skip.
        return $false
    }
}

$SkipReasons = @{
  Ext      = 0
  FileName = 0
  Dir      = 0
  Size     = 0
  Binary   = 0
  UserExcl = 0
}

function ShouldKeepByManifest([string]$name){ return $IncludeManifests -and ($ManifestKeep -contains $name) }

function ShouldSkip([System.IO.FileInfo]$file){
    $rp = RelPath $file.FullName
    $name = $file.Name
    $ext = $file.Extension.ToLower()

    if (ShouldKeepByManifest $name) { return $false }
    if ($Include -and ($Include | Where-Object { $rp -match $_ })) { return $false }

    if ($DefaultExcludedExts -contains $ext) { $SkipReasons.Ext++; return $true }
    if ($DefaultExcludedFiles -contains $name) { $SkipReasons.FileName++; return $true }

    foreach ($d in $DefaultExcludedDirs) {
        $sep = '[\\/]'
        $dirPattern = "(^|$sep)" + [regex]::Escape($d) + "($sep|$)"
        if ($rp -match $dirPattern) { $SkipReasons.Dir++; return $true }
    }

    if ($UserExclude -and ($UserExclude | Where-Object { $rp -match $_ })) { $SkipReasons.UserExcl++; return $true }

    $maxBytes = $MaxFileMB * 1MB
    if ($file.Length -gt $maxBytes -and -not (ShouldKeepByManifest $name)) { $SkipReasons.Size++; return $true }

    if (IsLikelyBinary $file.FullName -and -not (ShouldKeepByManifest $name)) { $SkipReasons.Binary++; return $true }

    return $false
}


# Expanded secret patterns
$SecretPatterns = @(
    # AWS
    '(?i)\bAKIA[0-9A-Z]{16}\b',
    '(?i)\baws_secret_access_key\s*[:=]\s*[A-Za-z0-9\/+=]{40}\b',
    # Azure SAS
    '(?i)\bsv=\d{4}-\d{2}-\d{2}&sig=[A-Za-z0-9%\/+=]{10,}\b',
    # Google API
    '(?i)\bAIza[0-9A-Za-z\-_]{35}\b',
    # GitHub tokens
    '(?i)\bghp_[A-Za-z0-9]{36,}\b',
    '(?i)\bgithub_pat_[A-Za-z0-9_]{22,}\b',
    # Slack
    '(?i)\bxox[baprs]-[A-Za-z0-9-]{10,}\b',
    # Stripe
    '(?i)\bsk_(live|test)_[A-Za-z0-9]{10,}\b',
    # Generic JWT
    '(?i)\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b',
    # PEM blocks
    '(?s)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    # Generic api key / secret / password
    '(?i)\b(secret|password|passwd|pwd|api[_-]?key|token|client[_-]?secret)\s*[:=]\s*["''][A-Za-z0-9\/+=._-]{12,}["'']',
    # Connection strings
    '(?i)\b(postgres|mysql|mssql|mongodb|amqp|redis|rediss|jdbc):\/\/[^ \r\n"]{10,}\b'
)

function Redact($text){
    if (-not $RedactSecrets) { return $text }
    $red = $text
    foreach ($rx in $SecretPatterns) {
        $red = [regex]::Replace($red, $rx, '[REDACTED]')
    }
    return $red
}

function Show-Tree {
    param ([string]$path,[string]$indent = "",[bool]$last = $true,[ref]$outputLines)
    $name = Split-Path $path -Leaf
    $marker = if ($last) { "└── " } else { "├── " }
    $outputLines.Value += "$indent$marker$name"
    $childIndent = if ($last) { "$indent    " } else { "$indent│   " }
    $items = @( Get-ChildItem -Path $path -Force | Where-Object {
        $_.Name -ne '.' -and $_.Name -ne '..' -and -not ($DefaultExcludedDirs -contains $_.Name)
    } | Sort-Object { if ($_.PSIsContainer) { "0$($_.Name)" } else { "1$($_.Name)" } })
    if (-not $items -or $items.Count -eq 0) { return }
    for ($i = 0; $i -lt $items.Count; $i++) {
        $isLast = ($i -eq $items.Count - 1)
        $item = $items[$i]
        if ($item.PSIsContainer) { Show-Tree -path $item.FullName -indent $childIndent -last $isLast -outputLines $outputLines }
        else { $outputLines.Value += "$childIndent├── $($item.Name)" }
    }
}

Write-Info "Scanning files under: $Root"
$AllFiles = Get-ChildItem -Path $Root -Recurse -File -Force -ErrorAction SilentlyContinue
$KeptFiles = New-Object System.Collections.Generic.List[System.IO.FileInfo]
$Skipped = New-Object System.Collections.Generic.List[string]

foreach ($f in $AllFiles) {
    if (ShouldSkip $f) { $Skipped.Add((RelPath $f.FullName)); continue }
    $KeptFiles.Add($f)
}

Write-Info "Writing monolithic inference file..."
New-Item -ItemType File -Path $MonoFile -Force | Out-Null
$monoWriter = [System.IO.StreamWriter]::new($MonoFile, $false, [System.Text.Encoding]::UTF8)

foreach ($f in $KeptFiles) {
    try {
        $rp = RelPath $f.FullName
        $monoWriter.WriteLine("==================")
        $monoWriter.WriteLine("Path: $rp")
        $monoWriter.WriteLine("==================")
        $monoWriter.WriteLine()

        $content = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
        $content = Redact $content
        $monoWriter.WriteLine($content.TrimEnd())
        $monoWriter.WriteLine()
    } catch {
        $monoWriter.WriteLine("/* ERROR READING FILE: $($f.FullName) */")
        $monoWriter.WriteLine()
    }
}
$monoWriter.Flush(); $monoWriter.Close()

Write-Info "Writing directory tree..."
$treeOut = @()
$treeOut += (Split-Path $Root -Leaf)
Show-Tree -path $Root -outputLines ([ref]$treeOut)
$treeOut | Set-Content -Path $TreeFile -Encoding UTF8

$HasGit = Test-Path (Join-Path $Root ".git")
$gitSummary = $null
if (-not $SkipGit -and $HasGit) {
    try {
        Push-Location $Root
        & git log --pretty=format:"%h %ad %an%n%B`n---" --date=short -n $GitLastN | Out-File -FilePath $GitLogFile -Encoding UTF8
        $tags     = (& git describe --tags 2>$null) -join "`n"
        $branches = (& git branch -vv        2>$null) -join "`n"
        $remotes  = (& git remote -v         2>$null) -join "`n"
        $shortlog = (& git shortlog -sn      2>$null) -join "`n"
        Pop-Location
        $remotes = [regex]::Replace($remotes, '(https?:\/\/)[^@]+@', '$1')
        $gitSummary = [PSCustomObject]@{
            tags = $tags; branches = $branches; remotes_sanitized = $remotes; contributors_shortlog = $shortlog
        }
        Add-Content $Summary ("`n--- GIT CONTEXT ---`nTags/Describe:`n$tags`n`nBranches:`n$branches`n`nRemotes:`n$remotes`n`nContributors (shortlog):`n$shortlog`n")
    } catch {
        Write-Warn "Git extraction failed: $_"
    }
} elseif (-not $HasGit) {
    Write-Info "No .git directory found; skipping Git extraction."
}

Write-Info "Building language/LOC summary..."
$extStats = @{}
$totalLOC = 0
foreach ($f in $KeptFiles) {
    $ext = $f.Extension.ToLower()
    if (-not $extStats.ContainsKey($ext)) { $extStats[$ext] = [PSCustomObject]@{ Count=0; Bytes=0; LOC=0 } }
    $s = $extStats[$ext]; $s.Count++; $s.Bytes += $f.Length
    try { $loc = (Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue).Count; $s.LOC += $loc; $totalLOC += $loc } catch {}
}

$largest = $KeptFiles | Sort-Object Length -Descending | Select-Object -First $LargestFilesTopN | ForEach-Object {
    [PSCustomObject]@{ SizeKB = [math]::Round($_.Length/1KB,1); Path = (RelPath $_.FullName) }
}

$summaryLines = @()
$summaryLines += "Snapshot Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
$summaryLines += "Root: $Root"
$summaryLines += "Output: $OutputDir"
$summaryLines += "Files kept: $($KeptFiles.Count) / scanned: $($AllFiles.Count)"
$summaryLines += "MaxFileMB: $MaxFileMB; RedactSecrets: $RedactSecrets"
$summaryLines += ""
$summaryLines += "By Extension (Count, LOC, KB):"
foreach ($k in ($extStats.Keys | Sort-Object)) {
    $s = $extStats[$k]; $kb = [math]::Round($s.Bytes/1KB,1)
    $summaryLines += ("  {0,-6}  files={1,5}  loc={2,7}  size={3,8} KB" -f $k, $s.Count, $s.LOC, $kb)
}
$summaryLines += ""
$summaryLines += "Skip reasons:"
$summaryLines += "  By extension: $($SkipReasons.Ext)"
$summaryLines += "  By file name: $($SkipReasons.FileName)"
$summaryLines += "  By directory: $($SkipReasons.Dir)"
$summaryLines += "  By user exclude: $($SkipReasons.UserExcl)"
$summaryLines += "  By size: $($SkipReasons.Size)"
$summaryLines += "  Binary heuristic: $($SkipReasons.Binary)"
$summaryLines += ""
$summaryLines += "Total LOC (approx): $totalLOC"
$summaryLines += ""
$summaryLines += "Largest $LargestFilesTopN kept files:"
foreach ($l in $largest) { $summaryLines += ("  {0,8} KB  {1}" -f $l.SizeKB, $l.Path) }
$summaryLines | Set-Content -Path $Summary -Encoding UTF8

$readmeText = @"
# LLM Snapshot

- Root: $Root
- Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')
- Monolith: $(Split-Path $MonoFile -Leaf)
- Tree: $(Split-Path $TreeFile -Leaf)
- Git log: $(if (Test-Path $GitLogFile) { (Split-Path $GitLogFile -Leaf) } else { "N/A" })
- Summary: $(Split-Path $Summary -Leaf)

## Notes
- Secrets redaction: $RedactSecrets
- Max file size: ${MaxFileMB}MB
- Manifests preserved: $IncludeManifests
- Files kept: $($KeptFiles.Count) / scanned: $($AllFiles.Count)
"@
$readmeText | Set-Content -Path $SnapshotReadme -Encoding UTF8

# --- NEW: emit machine-readable metadata JSON
if ($EmitMetadataJson) {
    $extList = @()
    foreach ($k in $extStats.Keys) {
        $s = $extStats[$k]
        $extList += [PSCustomObject]@{ ext=$k; files=$s.Count; loc=$s.LOC; bytes=$s.Bytes }
    }
    $meta = [PSCustomObject]@{
        created_utc = (Get-Date).ToUniversalTime()
        root = $Root
        files_scanned = $AllFiles.Count
        files_kept    = $KeptFiles.Count
        max_file_mb   = $MaxFileMB
        redacted      = [bool]$RedactSecrets
        largest_files = $largest
        by_extension  = $extList
        total_loc     = $totalLOC
        git_summary   = $gitSummary
    }
    $meta | ConvertTo-Json -Depth 6 | Out-File -FilePath $MetaJson -Encoding UTF8
}

if ($Zip) {
    $zipPath = "$OutputDir.zip"
    Write-Info "Zipping snapshot → $zipPath"
    Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    [System.IO.Compression.ZipFile]::CreateFromDirectory($OutputDir, $zipPath)
}

Write-Host ""
Write-Host "✅ Monolithic snapshot: $MonoFile"    -ForegroundColor Green
Write-Host "✅ Directory tree:       $TreeFile"   -ForegroundColor Green
if (Test-Path $GitLogFile) { Write-Host "✅ Git commit messages: $GitLogFile" -ForegroundColor Green }
Write-Host "✅ Summary:              $Summary"    -ForegroundColor Green
if ($EmitMetadataJson) { Write-Host "✅ Meta JSON:            $MetaJson"     -ForegroundColor Green }
if ($Zip) { Write-Host "✅ Zip:                  $OutputDir.zip" -ForegroundColor Green }
Write-Host ""
