param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$SourceCommit,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]{1,12}$')]
    [string]$SourceDateEpoch,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$HbbCommonCommit,

    [Parameter(Mandatory = $true)]
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$expectedUpstreamCommit = '6c578292e8ebbbec708b76986ba8c4bc7c509747'
$sciterCommit = 'f33df075d9eb2f8d252cb88f1b2c8096e56197ed'
$sciterBytes = 8296448L
$sciterSha256 = '4d97528e157c55ef1fabe9e37a9697116ab66660d7da6163f90a3a7abf80dd56'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$resolvedOutputParent = (Resolve-Path (Split-Path $OutputRoot -Parent)).Path
$canonicalOutputRoot = Join-Path $resolvedOutputParent (Split-Path $OutputRoot -Leaf)
if ($OutputRoot -cne $canonicalOutputRoot -or
    $canonicalOutputRoot -notlike "$env:RUNNER_TEMP\*") {
    throw 'The managed build output root is not canonical runner scratch.'
}
if (Test-Path -LiteralPath $canonicalOutputRoot) {
    throw 'The managed build output root is not clean.'
}

foreach ($identityName in @(
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL',
    'AZURE_CLIENT_ID', 'AZURE_TENANT_ID', 'AZURE_CLIENT_SECRET',
    'AZURE_FEDERATED_TOKEN_FILE'
)) {
    if (-not [string]::IsNullOrEmpty(
        [Environment]::GetEnvironmentVariable($identityName, 'Process')
    )) {
        throw "Credential-free managed build received forbidden identity variable: $identityName"
    }
}

$head = (& git -C $repositoryRoot rev-parse HEAD 2>&1 | Out-String).Trim()
$hbbHead = (& git -C (Join-Path $repositoryRoot 'libs\hbb_common') rev-parse HEAD 2>&1 |
    Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne $SourceCommit -or
    $hbbHead -cne $HbbCommonCommit) {
    throw 'The managed build checkout does not match its exact source contract.'
}
& git -C $repositoryRoot merge-base --is-ancestor $expectedUpstreamCommit $SourceCommit
if ($LASTEXITCODE -ne 0) {
    throw 'The managed build source is not descended from the exact upstream commit.'
}
$dirty = (& git -C $repositoryRoot status --porcelain --untracked-files=all 2>&1 |
    Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $dirty) {
    throw 'The managed build checkout is not clean.'
}

[long]$epoch = 0
if (-not [long]::TryParse(
    $SourceDateEpoch,
    [Globalization.NumberStyles]::None,
    [Globalization.CultureInfo]::InvariantCulture,
    [ref]$epoch
) -or $epoch -lt 0 -or
    $SourceDateEpoch -cne $epoch.ToString([Globalization.CultureInfo]::InvariantCulture)) {
    throw 'The managed source epoch is not canonical.'
}
$buildDate = [DateTimeOffset]::FromUnixTimeSeconds($epoch).UtcDateTime.ToString(
    'yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture
)

[void](New-Item -ItemType Directory -Path $canonicalOutputRoot)
$runtimeRoot = Join-Path $canonicalOutputRoot 'runtime'
[void](New-Item -ItemType Directory -Path $runtimeRoot)
$sciterPath = Join-Path $runtimeRoot 'sciter.dll'
$sciterUri = "https://raw.githubusercontent.com/c-smile/sciter-sdk/$sciterCommit/bin.win/x64/sciter.dll"
$previousProgress = $ProgressPreference
try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -UseBasicParsing -Uri $sciterUri -OutFile $sciterPath
} finally {
    $ProgressPreference = $previousProgress
}
$sciterItem = Get-Item -LiteralPath $sciterPath -Force
if ($sciterItem.PSIsContainer -or
    ($sciterItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $sciterItem.Length -ne $sciterBytes -or
    (Get-FileHash -LiteralPath $sciterPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $sciterSha256) {
    throw 'The pinned Sciter runtime download is not exact.'
}

$previousLocation = Get-Location
$savedEnvironment = @{}
foreach ($name in @(
    'SOURCE_DATE_EPOCH', 'SIT_RUSTDESK_FORK_COMMIT', 'CARGO_INCREMENTAL',
    'CARGO_PROFILE_RELEASE_INCREMENTAL',
    'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS', 'CL', '_LINK_'
)) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    Set-Location $repositoryRoot
    $env:SOURCE_DATE_EPOCH = $SourceDateEpoch
    $env:SIT_RUSTDESK_FORK_COMMIT = $SourceCommit
    $env:CARGO_INCREMENTAL = '0'
    $env:CARGO_PROFILE_RELEASE_INCREMENTAL = 'false'
    $mappedSource = 'Z:\src\rustdesk-client'
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = (
        "-Ctarget-feature=+crt-static -Clink-arg=/Brepro " +
        "--remap-path-prefix=$repositoryRoot=$mappedSource"
    )
    $env:CL = '/Brepro'
    $env:_LINK_ = '/Brepro'

    & python res\inline-sciter.py
    if ($LASTEXITCODE -ne 0) { throw 'Managed Sciter resource generation failed.' }
    & cargo build --locked --target x86_64-pc-windows-msvc `
        --features inline,vram,hwcodec --release --bins
    if ($LASTEXITCODE -ne 0) { throw 'Managed Windows RustDesk build failed.' }
} finally {
    Set-Location $previousLocation
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable(
            $name, $savedEnvironment[$name], 'Process'
        )
    }
}

$builtExecutable = Join-Path $repositoryRoot (
    'target\x86_64-pc-windows-msvc\release\rustdesk.exe'
)
$candidatePath = Join-Path $canonicalOutputRoot 'rustdesk-client.exe'
$builtItem = Get-Item -LiteralPath $builtExecutable -Force -ErrorAction Stop
if ($builtItem.PSIsContainer -or
    ($builtItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $builtItem.Length -lt 1 -or $builtItem.Length -gt 512MB) {
    throw 'The managed Windows executable is not one bounded regular file.'
}
Copy-Item -LiteralPath $builtExecutable -Destination $candidatePath
$signature = Get-AuthenticodeSignature -LiteralPath $candidatePath
if ($signature.Status -cne 'NotSigned' -or $null -ne $signature.SignerCertificate) {
    throw 'The credential-free builder did not produce one unsigned executable.'
}

$buildInformation = [ordered]@{
    schema = 1
    source_commit = $SourceCommit
    upstream_commit = $expectedUpstreamCommit
    hbb_common_commit = $HbbCommonCommit
    source_date_epoch = $SourceDateEpoch
    build_date_utc = $buildDate
    target = 'x86_64-pc-windows-msvc'
    rust_toolchain = (& rustc -Vv | Out-String).Trim()
    cargo = (& cargo -V | Out-String).Trim()
    features = @('inline', 'vram', 'hwcodec')
    sciter = [ordered]@{
        commit = $sciterCommit
        bytes = $sciterBytes
        sha256 = $sciterSha256
    }
    executable = [ordered]@{
        name = 'rustdesk-client.exe'
        bytes = (Get-Item -LiteralPath $candidatePath).Length
        sha256 = (Get-FileHash -LiteralPath $candidatePath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$buildInformation | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath (Join-Path $canonicalOutputRoot 'build-information.json') `
        -Encoding utf8NoBOM

$inventory = @(Get-ChildItem -LiteralPath $canonicalOutputRoot -Recurse -File |
    ForEach-Object {
        [pscustomobject]@{
            Path = [IO.Path]::GetRelativePath($canonicalOutputRoot, $_.FullName).Replace('\', '/')
            Length = $_.Length
            SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    } | Sort-Object Path)
if (($inventory.Path -join "`n") -cne (
    "build-information.json`nruntime/sciter.dll`nrustdesk-client.exe"
)) {
    throw 'The managed build output inventory is not exact.'
}
$inventory | Format-Table -AutoSize
