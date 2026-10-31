# AEGIS one-command install (Windows PowerShell 5.1+). Free and local: no accounts, no paid services.
#
#   irm https://raw.githubusercontent.com/aaronsunny007/AI-CySec-defence-system/main/install.ps1 | iex
#   or, from a clone:  .\install.ps1
#
# Gets the source if needed, makes sure a Go toolchain exists (downloads the official zip into
# %USERPROFILE%\.aegis\go - no admin rights), builds the gateway, and adds an `aegis` command to your PATH.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$RepoUrl = if ($env:AEGIS_REPO) { $env:AEGIS_REPO } else { "https://github.com/aaronsunny007/AI-CySec-defence-system.git" }
$Ref     = if ($env:AEGIS_REF)  { $env:AEGIS_REF }  else { "main" }
$Home_   = if ($env:AEGIS_HOME) { $env:AEGIS_HOME } else { Join-Path $env:USERPROFILE ".aegis" }
$GoIndex = if ($env:AEGIS_GO_INDEX) { $env:AEGIS_GO_INDEX } else { "https://go.dev/dl/?mode=json&include=all" }
$GoBootstrap = "1.24.7"      # any Go >= 1.21 works: gateway/go.mod makes Go fetch the exact toolchain itself

function Die($m) { Write-Host "install: $m" -ForegroundColor Red; exit 1 }

function Install-Aegis {
    # --- python ------------------------------------------------------------------------
    $py = $null
    foreach ($c in @("python", "py")) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($cmd) {
            & $cmd.Source -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) { $py = $cmd.Source; break }
        }
    }
    if (-not $py) { Die "Python 3.10+ is required (https://www.python.org/downloads/), then re-run." }

    # --- source --------------------------------------------------------------------------
    $here = if ($PSScriptRoot) { $PSScriptRoot } else { $null }
    if ($here -and (Test-Path (Join-Path $here "aegis.py"))) {
        $Src = $here
    } else {
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Die "git is required to fetch AEGIS (or download the repo zip and run .\install.ps1 from it)." }
        $Src = Join-Path $Home_ "src"
        New-Item -ItemType Directory -Force $Home_ | Out-Null
        if (Test-Path (Join-Path $Src ".git")) {
            Write-Host "Updating $Src ..."
            git -C $Src fetch --depth 1 origin $Ref; git -C $Src checkout -q FETCH_HEAD
        } else {
            Write-Host "Fetching AEGIS into $Src ..."
            git clone --depth 1 --branch $Ref $RepoUrl $Src
        }
    }

    # --- go ----------------------------------------------------------------------------------
    function GoOk($exe) {
        try {
            $v = (& $exe version) -replace '^go version go(\d+)\.(\d+).*', '$1.$2'
            $p = $v.Split('.'); return ([int]$p[0] -gt 1) -or ([int]$p[0] -eq 1 -and [int]$p[1] -ge 21)
        } catch { return $false }
    }
    $go = $null
    $sys = Get-Command go -ErrorAction SilentlyContinue
    $own = Join-Path $Home_ "go\bin\go.exe"
    if ($sys -and (GoOk $sys.Source)) { $go = $sys.Source }
    elseif ((Test-Path $own) -and (GoOk $own)) { $go = $own }
    else {
        $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
        $fname = "go$GoBootstrap.windows-$arch.zip"
        $url = "https://go.dev/dl/$fname"
        Write-Host "No Go toolchain found - downloading the official one to $Home_\go ($url) ..."
        New-Item -ItemType Directory -Force $Home_ | Out-Null
        $zip = Join-Path $Home_ "go.zip"
        Invoke-WebRequest $url -OutFile $zip
        # Verify against the SHA-256 in the official download index; fail closed if it cannot be had.
        $want = $null
        try {
            $index = Invoke-RestMethod $GoIndex
            $want = ($index | ForEach-Object { $_.files } | Where-Object { $_.filename -eq $fname } | Select-Object -First 1).sha256
        } catch { }
        if (-not $want) { Remove-Item $zip -ErrorAction SilentlyContinue; Die "could not get the official SHA-256 for $fname from $GoIndex; not installing an unverified toolchain" }
        $got = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
        if ($got -ne $want.ToLower()) { Remove-Item $zip -ErrorAction SilentlyContinue; Die "SHA-256 mismatch for $fname (expected $want, got $got); download discarded" }
        Write-Host "Checksum verified."
        if (Test-Path (Join-Path $Home_ "go")) { Remove-Item -Recurse -Force (Join-Path $Home_ "go") }
        Expand-Archive $zip -DestinationPath $Home_ -Force
        Remove-Item $zip
        $go = $own
    }
    Write-Host "Using Go: $go"

    # --- build ---------------------------------------------------------------------------------
    Write-Host "Building the gateway (first build downloads Coraza + the OWASP Core Rule Set, about a minute) ..."
    New-Item -ItemType Directory -Force (Join-Path $Src "bin") | Out-Null
    Push-Location (Join-Path $Src "gateway")
    try {
        & $go build -o ..\bin\gateway.exe . ; if ($LASTEXITCODE) { Die "gateway build failed" }
        & $go build -o ..\bin\replay.exe .\cmd\replay ; if ($LASTEXITCODE) { Die "replay build failed" }
    } finally { Pop-Location }

    # --- command on PATH -------------------------------------------------------------------------
    # the launcher embeds these paths in a .cmd file: refuse characters cmd.exe would interpret inside it
    foreach ($p in @($Src, $py)) { if ($p -match '["%^!]') { Die "refusing a path containing a quote, %, ^ or !: $p" } }
    $binDir = Join-Path $Home_ "bin"
    New-Item -ItemType Directory -Force $binDir | Out-Null
    Set-Content -Path (Join-Path $binDir "aegis.cmd") -Encoding ASCII -Value "@echo off`r`ncd /d `"$Src`"`r`n`"$py`" `"$Src\aegis.py`" %*"
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (($userPath -split ";") -notcontains $binDir) {
        [Environment]::SetEnvironmentVariable("Path", ($userPath.TrimEnd(";") + ";" + $binDir), "User")
        Write-Host "Added $binDir to your PATH - open a NEW terminal for `aegis` to be found."
    }

    Write-Host ""
    Write-Host "AEGIS installed in $Src"
    Write-Host ""
    Write-Host "Next:"
    Write-Host "  aegis init --target http://127.0.0.1:3000     # the app you want to protect"
    Write-Host "  aegis doctor"
    Write-Host "  aegis learn                                   # observe-only: records your normal traffic"
    Write-Host "  aegis protect                                 # when learn has seen enough traffic"
}

Install-Aegis
