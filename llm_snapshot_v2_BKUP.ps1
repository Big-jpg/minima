param(
    [string]$ProjectFolder,
    [int]$MaxFileMB = 5,
    [switch]$RedactSecrets,
    [string[]]$Include,             # regex patterns (relative paths) to force-include
    [string[]]$Exclude,             # regex patterns (relative paths) to exclude
    [switch]$IncludeManifests = $true,
    [switch]$Zip = $true,
    [switch]$SkipGit,
    [int]$GitLastN = 400,
    [int]$LargestFilesTopN = 40,
    [string]$OutputDir              # optional custom output dir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info($msg){ Write-Host "• $msg" -ForegroundColor Cyan }
function Write-Warn($msg){ Write-Host "! $msg" -ForegroundColor Yellow }
function Write-Err ($msg){ Write-Host "✖ $msg" -ForegroundColor Red }

# --- Prompt for folder if not provided ---
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

# --- Default excludes (dirs & files) ---
$DefaultExcludedDirs = @(
  # language/build caches
  'node_modules','.next','.turbo','dist','build','out','public','__pycache__','.venv','venv','.mypy_cache',
  '.pytest_cache','bin','pkg','target','.gradle','.idea','.vs','obj','.vscode','.cache','.vercel','.terraform',
  '.git','coverage'
)

$DefaultExcludedExts = @(
  # images & binaries
  '.png','.jpg','.jpeg','.gif','.webp','.ico','.svg',
  '.exe','.dll','.zip','.7z','.tar','.gz','.rar',
  # media
  '.mp4','.mov','.avi','.mkv','.wav','.mp3','.flac',
  # bytecode/compiled
  '.pyc','.class','.o','.so','.a','.dylib',
  # docs/archives
  '.pdf','.docx','.pptx','.xlsx'
)

$DefaultExcludedFiles = @(
  # locks & system
  'package-lock.json','yarn.lock','pnpm-lock.yaml','Cargo.lock','go.sum',
  '.classpath','.project','.settings','.DS_Store','Thumbs.db','.editorconfig','.coverage','.envrc','.env.local','.env'
)

# --- Manifests we TRY to keep (they are gold for install docs) ---
$ManifestKeep = @(
  'package.json','pyproject.toml','requirements.txt','Pipfile','Pipfile.lock',
  'setup.py','poetry.lock','go.mod','go.work','Cargo.toml',
  'CMakeLists.txt','Makefile','build.gradle','pom.xml','Gemfile','composer.json'
)

# Merge user excludes
$UserExclude = $Exclude

# --- Helpers ---
function RelPath([string]$full){ return $full.Substring($Root.Length).TrimStart('\','/') }

function IsLikelyBinary([string]$path) {
    try {
        $fs = [System.IO.File]::OpenRead($path)
        $buf = New-Object byte[] 8000
        $read = $fs.Read($buf,0,$buf.Length)
        $fs.Close()
        if ($read -eq 0) { return $false }
        # Heuristic: non-text ratio threshold
        $nonText = 0
        for ($i=0; $i -lt $read; $i++){
            $b = $buf[$i]
            if (($b -eq 0) -or ($b -lt 9) -or (($b -ge 14) -and ($b -le 31))) { $nonText++ }
        }
        return ($nonText / $read) -gt 0.30
    } catch { return $true }
}

function ShouldKeepByManifest([string]$name){
    return $IncludeManifests -and ($ManifestKeep -contains $name)
}

function ShouldSkip([System.IO.FileInfo]$file){
    $rp = RelPath $file.FullName
    $name = $file.Name
    $ext = $file.Extension.ToLower()

    # manifest whitelist override
    if (ShouldKeepByManifest $name) { return $false }

    # user include overrides everything
    if ($Include -and ($Include | Where-Object { $rp -match $_ })) { return $false }

    # default excludes
    if ($DefaultExcludedExts -contains $ext) { return $true }
    if ($DefaultExcludedFiles -contains $name) { return $true }
    foreach ($d in $DefaultExcludedDirs) {
        if ($file.FullName -match [regex]::Escape([System.IO.Path]::DirectorySeparatorChar + $d + [System.IO.Path]::DirectorySeparatorChar) `
            -or $file.FullName -like "*$([System.IO.Path]::DirectorySeparatorChar)$d") { return $true }
    }

    # user excludes
    if ($UserExclude -and ($UserExclude | Where-Object { $rp -match $_ })) { return $true }

    # size
    $maxBytes = $MaxFileMB * 1MB
    if ($file.Length -gt $maxBytes -and -not (ShouldKeepByManifest $name)) { return $true }

    # binary sniff
    if (IsLikelyBinary $file.FullName -and -not (ShouldKeepByManifest $name)) { return $true }

    return $false
}

# --- Redaction (opt-in) ---
$SecretPatterns = @(
    # AWS Access Key ID (AKIA...)
    '(?i)\bAKIA[0-9A-Z]{16}\b',
    # AWS Secret Key
    '(?i)\baws_secret_access_key\s*[:=]\s*[A-Za-z0-9\/+=]{40}\b',
    # Azure connection string / keys
    '(?i)(DefaultEndpointsProtocol|AccountName|AccountKey|EndpointSuffix)\s*=\s*[A-Za-z0-9+\/=;\.:_-]+',
    # Generic bearer/JWT
    '(?i)\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,})\b',
    # Generic password/secret api key-ish
    '(?i)\b(secret|password|passwd|pwd|api[_-]?key|token)\s*[:=]\s*["'']?[A-Za-z0-9\/+=._-]{12,}["'']?'
)

function Redact($text){
    if (-not $RedactSecrets){ return $text }
    $red = $text
    foreach ($rx in $SecretPatterns) {
        $red = [regex]::Replace($red, $rx, '[REDACTED]')
    }
    return $red
}

# --- Tree printer (ASCII) ---
function Show-Tree {
    param (
        [string]$path,
        [string]$indent = "",
        [bool]$last = $true,
        [ref]$outputLines
    )

    $name = Split-Path $path -Leaf
    $marker = if ($last) { "└── " } else { "├── " }
    $outputLines.Value += "$indent$marker$name"

    $childIndent = if ($last) { "$indent    " } else { "$indent│   " }

    # Force array so .Count is always valid, even for a single child
    $items = @( Get-ChildItem -Path $path -Force | Where-Object {
        $_.Name -ne '.' -and $_.Name -ne '..' -and
        -not ($DefaultExcludedDirs -contains $_.Name)
    } | Sort-Object {
        if ($_.PSIsContainer) { "0$($_.Name)" } else { "1$($_.Name)" }
    })

    if (-not $items -or $items.Count -eq 0) { return }

    for ($i = 0; $i -lt $items.Count; $i++) {
        $isLast = ($i -eq $items.Count - 1)
        $item = $items[$i]
        if ($item.PSIsContainer) {
            Show-Tree -path $item.FullName -indent $childIndent -last $isLast -outputLines $outputLines
        } else {
            $outputLines.Value += "$childIndent├── $($item.Name)"
        }
    }
}


# --- Collect files ---
Write-Info "Scanning files under: $Root"
$AllFiles = Get-ChildItem -Path $Root -Recurse -File -Force -ErrorAction SilentlyContinue
$KeptFiles = New-Object System.Collections.Generic.List[System.IO.FileInfo]
$Skipped = New-Object System.Collections.Generic.List[string]

foreach ($f in $AllFiles) {
    if (ShouldSkip $f) { $Skipped.Add((RelPath $f.FullName)); continue }
    $KeptFiles.Add($f)
}

# --- Write monolithic file (streamed) ---
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

        $sr = [System.IO.StreamReader]::new($f.FullName, [System.Text.Encoding]::UTF8, $true)
        $content = $sr.ReadToEnd()
        $sr.Close()

        $content = Redact $content
        $monoWriter.WriteLine($content.TrimEnd())
        $monoWriter.WriteLine()
    } catch {
        $monoWriter.WriteLine("/* ERROR READING FILE: $($f.FullName) */")
        $monoWriter.WriteLine()
    }
}
$monoWriter.Flush(); $monoWriter.Close()

# --- Directory tree ---
Write-Info "Writing directory tree..."
$treeOut = @()
$treeOut += (Split-Path $Root -Leaf)
Show-Tree -path $Root -outputLines ([ref]$treeOut)
$treeOut | Set-Content -Path $TreeFile -Encoding UTF8

# --- Git extraction (optional) ---
$HasGit = Test-Path (Join-Path $Root ".git")
if (-not $SkipGit -and $HasGit) {
    try {
        Push-Location $Root

        # Commit messages (bounded)
        & git log --pretty=format:"%h %ad %an%n%B`n---" --date=short -n $GitLastN | Out-File -FilePath $GitLogFile -Encoding UTF8

        # Extras for summary (sanitized)
        $tags     = (& git describe --tags 2>$null) -join "`n"
        $branches = (& git branch -vv        2>$null) -join "`n"
        $remotes  = (& git remote -v         2>$null) -join "`n"
        $shortlog = (& git shortlog -sn      2>$null) -join "`n"

        Pop-Location

        # Sanitize remotes (strip tokens if any accidental)
        $remotes = [regex]::Replace($remotes, '(https?:\/\/)[^@]+@', '$1')

        Add-Content $Summary ("`n--- GIT CONTEXT ---`n")
        Add-Content $Summary ("Tags/Describe:`n$tags`n")
        Add-Content $Summary ("Branches:`n$branches`n")
        Add-Content $Summary ("Remotes:`n$remotes`n")
        Add-Content $Summary ("Contributors (shortlog):`n$shortlog`n")
    } catch {
        Write-Warn "Git extraction failed: $_"
    }
} elseif (-not $HasGit) {
    Write-Info "No .git directory found; skipping Git extraction."
}

# --- Language/LOC summary & largest files ---
Write-Info "Building language/LOC summary..."
$extStats = @{}
$totalLOC = 0
foreach ($f in $KeptFiles) {
    $ext = $f.Extension.ToLower()
    if (-not $extStats.ContainsKey($ext)) {
        $extStats[$ext] = [PSCustomObject]@{ Count=0; Bytes=0; LOC=0 }
    }
    $s = $extStats[$ext]
    $s.Count++
    $s.Bytes += $f.Length
    try {
        $loc = (Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue).Count
        $s.LOC += $loc; $totalLOC += $loc
    } catch {}
}

$largest = $KeptFiles | Sort-Object Length -Descending | Select-Object -First $LargestFilesTopN | ForEach-Object {
    [PSCustomObject]@{ SizeKB = [math]::Round($_.Length/1KB,1); Path = (RelPath $_.FullName) }
}

# Write summary
$summaryLines = @()
$summaryLines += "Snapshot Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
$summaryLines += "Root: $Root"
$summaryLines += "Output: $OutputDir"
$summaryLines += "Files kept: $($KeptFiles.Count) / scanned: $($AllFiles.Count)"
$summaryLines += "MaxFileMB: $MaxFileMB; RedactSecrets: $RedactSecrets"
$summaryLines += ""
$summaryLines += "By Extension (Count, LOC, KB):"
foreach ($k in ($extStats.Keys | Sort-Object)) {
    $s = $extStats[$k]
    $kb = [math]::Round($s.Bytes/1KB,1)
    $summaryLines += ("  {0,-6}  files={1,5}  loc={2,7}  size={3,8} KB" -f $k, $s.Count, $s.LOC, $kb)
}
$summaryLines += ""
$summaryLines += "Total LOC (approx): $totalLOC"
$summaryLines += ""
$summaryLines += "Largest $LargestFilesTopN kept files:"
foreach ($l in $largest) { $summaryLines += ("  {0,8} KB  {1}" -f $l.SizeKB, $l.Path) }
$summaryLines | Set-Content -Path $Summary -Encoding UTF8

# --- Snapshot README ---
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

This bundle is optimized for **LLM ingestion**: textual source, manifests, and configs are prioritized; large/binary/media files are excluded. If you need more/less content, rerun with `-Include`/`-Exclude`/`-MaxFileMB` or turn redaction on/off.

"@
$readmeText | Set-Content -Path $SnapshotReadme -Encoding UTF8

# --- Optional zip ---
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
if (Test-Path $GitLogFile) {
    Write-Host "✅ Git commit messages: $GitLogFile" -ForegroundColor Green
}
Write-Host "✅ Summary:              $Summary"    -ForegroundColor Green
if ($Zip) { Write-Host "✅ Zip:                  $OutputDir.zip" -ForegroundColor Green }
Write-Host ""