param(
    [Parameter(Mandatory = $true)]
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
Add-Type -AssemblyName System.IO.Compression.FileSystem

$resolvedOutputParent = (Resolve-Path (Split-Path $OutputRoot -Parent)).Path
$canonicalOutputRoot = Join-Path $resolvedOutputParent (Split-Path $OutputRoot -Leaf)
if ($OutputRoot -cne $canonicalOutputRoot -or
    $canonicalOutputRoot -notlike "$env:RUNNER_TEMP\*") {
    throw 'The offline signing-tool output root is not canonical runner scratch.'
}
if (Test-Path -LiteralPath $canonicalOutputRoot) {
    throw 'The offline signing-tool output root is not clean.'
}
foreach ($identityName in @(
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL',
    'AZURE_CLIENT_ID', 'AZURE_TENANT_ID', 'AZURE_CLIENT_SECRET',
    'AZURE_FEDERATED_TOKEN_FILE'
)) {
    if (-not [string]::IsNullOrEmpty(
        [Environment]::GetEnvironmentVariable($identityName, 'Process')
    )) {
        throw "Credential-free tool bootstrap received forbidden identity variable: $identityName"
    }
}

function Get-CanonicalTree {
    param([Parameter(Mandatory = $true)][string]$Root)

    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'An offline signing-tool root is unsafe.'
    }
    $entries = @(Get-ChildItem -LiteralPath $Root -Recurse -Force)
    if (@($entries | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    }).Count -ne 0) {
        throw 'An offline signing-tool tree contains a reparse point.'
    }
    $fileMap = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($file in @($entries | Where-Object { -not $_.PSIsContainer })) {
        $relative = [IO.Path]::GetRelativePath($Root, $file.FullName).Replace('\', '/')
        if ([string]::IsNullOrWhiteSpace($relative) -or
            $relative.StartsWith('/', [StringComparison]::Ordinal) -or
            $relative -match '[\x00-\x1f\x7f]' -or
            $relative.Split('/') -contains '..' -or
            $fileMap.ContainsKey($relative)) {
            throw 'An offline signing-tool tree contains an invalid path.'
        }
        $fileMap.Add($relative, $file)
    }
    [string[]]$paths = @($fileMap.Keys)
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    $records = [Collections.Generic.List[string]]::new()
    foreach ($relative in $paths) {
        $file = $fileMap[$relative]
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $records.Add(
            "$relative`t$($file.Length.ToString([Globalization.CultureInfo]::InvariantCulture))`t$hash"
        )
    }
    $serialized = ($records.ToArray() -join "`n") + "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($serialized)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $treeHash = ([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace(
            '-', ''
        ).ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
    return [pscustomobject]@{
        FileCount = $paths.Count
        ManifestBytes = $bytes.Length
        SHA256 = $treeHash
    }
}

function Assert-PinnedTree {
    param([Parameter(Mandatory = $true)][string]$Root)

    $actualRoot = @(Get-ChildItem -LiteralPath $Root -Force | Sort-Object Name)
    $expectedRoot = @('buildtools', 'client', 'dotnet') | Sort-Object
    if (($actualRoot.Name -join "`n") -cne ($expectedRoot -join "`n") -or
        @($actualRoot | Where-Object {
            -not $_.PSIsContainer -or
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        }).Count -ne 0) {
        throw 'Offline Artifact Signing tool root inventory is not exact.'
    }
    foreach ($contract in @(
        @('buildtools', 192, 22225, 'b9e7b3af121852f804a3aa85dda281b02f9eae6383ff5da8ecdadf4fe6e24586'),
        @('client', 93, 9345, '709ef91e442f85a9992a7d75a772ea37c44057d47dbf7c8dc3390c0230224610'),
        @('dotnet', 188, 25438, 'c1f9e26ca15bb2617094caffc4937fd8e3cd25a12592bcfc1a570a086d668211')
    )) {
        $tree = Get-CanonicalTree -Root (Join-Path $Root $contract[0])
        if ($tree.FileCount -ne $contract[1] -or
            $tree.ManifestBytes -ne $contract[2] -or
            $tree.SHA256 -cne $contract[3]) {
            throw "Offline Artifact Signing $($contract[0]) tree is not exact."
        }
    }
}

[void](New-Item -ItemType Directory -Path $canonicalOutputRoot)
$scratchRoot = Join-Path $env:RUNNER_TEMP 'sit-managed-signing-downloads'
if (Test-Path -LiteralPath $scratchRoot) {
    throw 'The offline signing-tool download root is not clean.'
}
[void](New-Item -ItemType Directory -Path $scratchRoot)
$packages = @(
    [pscustomobject]@{
        Name = 'Microsoft.Windows.SDK.BuildTools.10.0.26100.4188.nupkg'
        Uri = 'https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.buildtools/10.0.26100.4188/microsoft.windows.sdk.buildtools.10.0.26100.4188.nupkg'
        Bytes = 22380379L
        SHA256 = '180deb372659029864c10a0c04787833234d64aacd1d2c0661d2c00295d8e022'
        Destination = 'buildtools'
    },
    [pscustomobject]@{
        Name = 'Microsoft.ArtifactSigning.Client.1.0.128.nupkg'
        Uri = 'https://api.nuget.org/v3-flatcontainer/microsoft.artifactsigning.client/1.0.128/microsoft.artifactsigning.client.1.0.128.nupkg'
        Bytes = 14653224L
        SHA256 = '74bd7d27e6ce1051409c38d9b46bc8df0400ecd643d51ffbf2ac00869061e40b'
        Destination = 'client'
    },
    [pscustomobject]@{
        Name = 'dotnet-runtime-8.0.30-win-x64.zip'
        Uri = 'https://builds.dotnet.microsoft.com/dotnet/Runtime/8.0.30/dotnet-runtime-8.0.30-win-x64.zip'
        Bytes = 33251575L
        SHA256 = 'b712d3ca4462a04a7d2f81e57232135f63ac2202624b8cb7a9654d245199009d'
        Destination = 'dotnet'
    }
)
$previousProgress = $ProgressPreference
try {
    $ProgressPreference = 'SilentlyContinue'
    foreach ($package in $packages) {
        $archive = Join-Path $scratchRoot $package.Name
        Invoke-WebRequest -UseBasicParsing -Uri $package.Uri -OutFile $archive
        $item = Get-Item -LiteralPath $archive -Force
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.Length -ne $package.Bytes -or
            (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                $package.SHA256) {
            throw "Downloaded Microsoft signing dependency is not exact: $($package.Name)"
        }
        $destination = Join-Path $canonicalOutputRoot $package.Destination
        [void](New-Item -ItemType Directory -Path $destination)
        [IO.Compression.ZipFile]::ExtractToDirectory($archive, $destination)
    }
} finally {
    $ProgressPreference = $previousProgress
}
Assert-PinnedTree -Root $canonicalOutputRoot
Write-Output 'OFFLINE_SIGNING_TOOLS=PASS'
