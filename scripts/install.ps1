$ErrorActionPreference = 'Stop'
$Root = if ($env:ZK_SCRIBE_HOME) { $env:ZK_SCRIBE_HOME } else { Join-Path $env:USERPROFILE '.zk-scribe' }
$Package = if ($env:ZK_SCRIBE_PACKAGE) { $env:ZK_SCRIBE_PACKAGE } else { 'https://github.com/brian-mwirigi/ZK-Scribe/archive/refs/heads/main.tar.gz' }
$NodeVersion = 'v22.23.3'

function Get-NodeMajor([string]$Exe) {
  $raw = & $Exe -p "process.versions.node.split('.')[0]"
  return [int]("$raw".Trim())
}

$node = $null
$system = Get-Command node -ErrorAction SilentlyContinue
if ($system) {
  $major = Get-NodeMajor $system.Source
  if ($major -ge 22) { $node = $system.Source }
}

if (-not $node) {
  $arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } else { 'x64' }
  $asset = "node-$NodeVersion-win-$arch.zip"
  $url = "https://nodejs.org/dist/$NodeVersion/$asset"
  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("zk-scribe-node-" + [guid]::NewGuid().ToString('n'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  $zip = Join-Path $tmp 'node.zip'
  Invoke-WebRequest -Uri $url -OutFile $zip
  Expand-Archive -Path $zip -DestinationPath $tmp
  $extracted = Get-ChildItem $tmp -Directory | Where-Object { $_.Name -like 'node-*' } | Select-Object -First 1
  $dest = Join-Path $Root 'node'
  if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
  New-Item -ItemType Directory -Path $Root -Force | Out-Null
  Move-Item $extracted.FullName $dest
  $node = Join-Path $dest 'node.exe'
  Remove-Item -Recurse -Force $tmp
}

$npm = Join-Path (Split-Path $node) 'npm.cmd'
if (-not (Test-Path $npm)) {
  $found = Get-Command npm -ErrorAction SilentlyContinue
  if (-not $found) { throw 'npm was not found next to Node.js.' }
  $npm = $found.Source
}

New-Item -ItemType Directory -Path $Root -Force | Out-Null
& $npm install -g --prefix $Root $Package
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$bin = $Root
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if ($userPath -notlike "*$bin*") {
  $joined = if ($userPath) { "$userPath;$bin" } else { $bin }
  [Environment]::SetEnvironmentVariable('Path', $joined, 'User')
}
$env:Path = "$bin;$env:Path"
Write-Output 'Installed zk-scribe.'
Write-Output 'In the manuscript repository, run: zk-scribe init'
