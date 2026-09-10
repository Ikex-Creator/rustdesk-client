param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$SourceCommit,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]{1,12}$')]
    [string]$SourceDateEpoch,

    [Parameter(Mandatory = $true)]
    [string]$SignedExecutable,

    [Parameter(Mandatory = $true)]
    [string]$SciterRuntime,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^1\.3\.6\.1\.4\.1\.311\.97\.(?:[0-9]+\.)*[0-9]+$')]
    [string]$SubscriberEku,

    [Parameter(Mandatory = $true)]
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$resolvedOutputParent = (Resolve-Path (Split-Path $OutputRoot -Parent)).Path
$canonicalOutputRoot = Join-Path $resolvedOutputParent (Split-Path $OutputRoot -Leaf)
if ($OutputRoot -cne $canonicalOutputRoot -or
    $canonicalOutputRoot -notlike "$env:RUNNER_TEMP\*" -or
    (Test-Path -LiteralPath $canonicalOutputRoot)) {
    throw 'The managed package output root is not canonical clean runner scratch.'
}
foreach ($identityName in @(
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL',
    'AZURE_CLIENT_ID', 'AZURE_TENANT_ID', 'AZURE_CLIENT_SECRET',
    'AZURE_FEDERATED_TOKEN_FILE'
)) {
    if (-not [string]::IsNullOrEmpty(
        [Environment]::GetEnvironmentVariable($identityName, 'Process')
    )) {
        throw "Credential-free MSI packaging received forbidden identity variable: $identityName"
    }
}
$head = (& git -C $repositoryRoot rev-parse HEAD 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne $SourceCommit) {
    throw 'The managed MSI checkout is not the exact release source.'
}
[long]$epoch = 0
if (-not [long]::TryParse(
    $SourceDateEpoch,
    [Globalization.NumberStyles]::None,
    [Globalization.CultureInfo]::InvariantCulture,
    [ref]$epoch
) -or $epoch -lt 0 -or
    $SourceDateEpoch -cne $epoch.ToString([Globalization.CultureInfo]::InvariantCulture)) {
    throw 'The managed MSI source epoch is not canonical.'
}
$buildTime = [DateTimeOffset]::FromUnixTimeSeconds($epoch).UtcDateTime
$buildDate = $buildTime.ToString(
    'yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture
)

foreach ($record in @(
    @($SignedExecutable, 'rustdesk-client.exe', 512MB),
    @($SciterRuntime, 'sciter.dll', 32MB)
)) {
    $item = Get-Item -LiteralPath $record[0] -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Name -cne $record[1] -or $item.Length -lt 1 -or
        $item.Length -gt $record[2]) {
        throw "A managed MSI input is not one exact bounded regular file: $($record[1])"
    }
}
$signature = Get-AuthenticodeSignature -LiteralPath $SignedExecutable
if ($signature.Status -cne 'Valid' -or
    $null -eq $signature.SignerCertificate -or
    $null -eq $signature.TimeStamperCertificate) {
    throw 'MSI packaging rejected the signed managed executable trust result.'
}
$ekuOids = @($signature.SignerCertificate.Extensions | Where-Object {
    $_.Oid.Value -ceq '2.5.29.37'
} | ForEach-Object {
    $enhanced = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$_
    @($enhanced.EnhancedKeyUsages | ForEach-Object { $_.Value })
})
foreach ($required in @('1.3.6.1.5.5.7.3.3', '1.3.6.1.4.1.311.97.1.0', $SubscriberEku)) {
    if (@($ekuOids | Where-Object { $_ -ceq $required }).Count -ne 1) {
        throw 'MSI packaging rejected the signed executable EKU contract.'
    }
}
$sciterItem = Get-Item -LiteralPath $SciterRuntime -Force
if ($sciterItem.Length -ne 8296448L -or
    (Get-FileHash -LiteralPath $SciterRuntime -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        '4d97528e157c55ef1fabe9e37a9697116ab66660d7da6163f90a3a7abf80dd56') {
    throw 'MSI packaging rejected the pinned Sciter runtime.'
}

$distributionRoot = Join-Path $repositoryRoot 'sit-release-dist'
if (Test-Path -LiteralPath $distributionRoot) {
    throw 'The managed MSI distribution root is not clean.'
}
[void](New-Item -ItemType Directory -Path $distributionRoot)
Copy-Item -LiteralPath $SignedExecutable -Destination (
    Join-Path $distributionRoot 'RustDesk.exe'
)
Copy-Item -LiteralPath $SciterRuntime -Destination (
    Join-Path $distributionRoot 'sciter.dll'
)
foreach ($file in @(Get-ChildItem -LiteralPath $distributionRoot -File)) {
    $file.CreationTimeUtc = $buildTime
    $file.LastAccessTimeUtc = $buildTime
    $file.LastWriteTimeUtc = $buildTime
}

$nugetRoot = Join-Path $env:RUNNER_TEMP 'sit-managed-nuget'
$nugetPackages = Join-Path $env:RUNNER_TEMP 'sit-managed-nuget-packages'
$nugetHttpCache = Join-Path $env:RUNNER_TEMP 'sit-managed-nuget-http-cache'
foreach ($path in @($nugetRoot, $nugetPackages, $nugetHttpCache)) {
    if (Test-Path -LiteralPath $path) {
        throw 'A managed MSI NuGet root is not clean.'
    }
    [void](New-Item -ItemType Directory -Path $path)
}
$nugetPath = Join-Path $nugetRoot 'nuget.exe'
$previousProgress = $ProgressPreference
try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -UseBasicParsing `
        -Uri 'https://dist.nuget.org/win-x86-commandline/v6.11.1/nuget.exe' `
        -OutFile $nugetPath
} finally {
    $ProgressPreference = $previousProgress
}
$nugetItem = Get-Item -LiteralPath $nugetPath -Force
if ($nugetItem.PSIsContainer -or
    ($nugetItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $nugetItem.Length -ne 8593856L -or
    (Get-FileHash -LiteralPath $nugetPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        'c0ddc9cb0633c4607da7e8028eb4f91248c8b74e45a68b0c79fcfa7d78c2a481') {
    throw 'The managed MSI NuGet executable is not exact.'
}

$msiRoot = Join-Path $repositoryRoot 'res\msi'
$savedEnvironment = @{}
foreach ($name in @(
    'SOURCE_DATE_EPOCH', 'NUGET_PACKAGES', 'NUGET_HTTP_CACHE_PATH',
    'NUGET_XMLDOC_MODE', 'CL', '_LINK_'
)) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$previousLocation = Get-Location
try {
    Set-Location $msiRoot
    $env:SOURCE_DATE_EPOCH = $SourceDateEpoch
    $env:NUGET_PACKAGES = $nugetPackages
    $env:NUGET_HTTP_CACHE_PATH = $nugetHttpCache
    $env:NUGET_XMLDOC_MODE = 'skip'
    $env:CL = '/Brepro'
    $env:_LINK_ = '/Brepro'
    & python preprocess.py --arp -d ../../sit-release-dist `
        --version 1.4.9 --revision-version 1 --build-date $buildDate `
        --deterministic-seed symplifiedit-rustdesk-x64-v1
    if ($LASTEXITCODE -ne 0) { throw 'Deterministic MSI preprocessing failed.' }
    # preprocess.py resolves its inventory relative to res/msi, while WiX
    # resolves BuildDir relative to the Package project one directory below.
    # Rebase only the generated WiX lookup path; the scanned bytes remain the
    # exact protected distributionRoot above.
    $includesPath = Join-Path $msiRoot 'Package\Includes.wxi'
    $includesText = [IO.File]::ReadAllText($includesPath)
    $preprocessBuildDir = '<?define BuildDir="../../sit-release-dist" ?>'
    $wixBuildDir = '<?define BuildDir="../../../sit-release-dist" ?>'
    if ([Regex]::Matches(
        $includesText,
        [Regex]::Escape($preprocessBuildDir)
    ).Count -ne 1) {
        throw 'The generated WiX distribution path is not exact.'
    }
    [IO.File]::WriteAllText(
        $includesPath,
        $includesText.Replace($preprocessBuildDir, $wixBuildDir),
        (New-Object Text.UTF8Encoding($false, $true))
    )
    & $nugetPath restore msi.sln -PackagesDirectory packages `
        -Source https://api.nuget.org/v3/index.json -NonInteractive
    if ($LASTEXITCODE -ne 0) { throw 'Pinned MSI NuGet restore failed.' }
    & msbuild msi.sln -restore -m:1 -nr:false `
        -p:Configuration=Release -p:Platform=x64 -p:TargetVersion=Windows10 `
        -p:SITDeterministicBuild=true -p:Deterministic=true `
        -p:ContinuousIntegrationBuild=true -p:DebugSymbols=false -p:DebugType=None `
        -p:RestorePackagesPath=$nugetPackages `
        -p:RestoreSources=https://api.nuget.org/v3/index.json
    if ($LASTEXITCODE -ne 0) { throw 'Deterministic managed MSI build failed.' }
} finally {
    Set-Location $previousLocation
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable(
            $name, $savedEnvironment[$name], 'Process'
        )
    }
}

$msiCandidates = @(Get-ChildItem -LiteralPath (Join-Path $msiRoot 'Package\bin') `
    -Recurse -File -Filter 'Package.msi')
if ($msiCandidates.Count -ne 1 -or $msiCandidates[0].Length -lt 1 -or
    $msiCandidates[0].Length -gt 768MB) {
    throw 'The managed MSI build output is not one bounded package.'
}
$includes = Get-Content -LiteralPath (Join-Path $msiRoot 'Package\Includes.wxi') -Raw
if ($includes.IndexOf(
    '<?define BuildDir="../../../sit-release-dist" ?>',
    [StringComparison]::Ordinal
) -lt 0) {
    throw 'The final WiX distribution path is not exact.'
}
$packageCodeMatch = [Regex]::Match(
    $includes,
    '(?m)^\s*<\?define PackageCode="(?<guid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})" \?>\s*$'
)
if (-not $packageCodeMatch.Success -or
    [Regex]::Matches($includes, '<\?define PackageCode=').Count -ne 1) {
    throw 'The deterministic MSI package identity is not exact.'
}
$packageCode = '{' + $packageCodeMatch.Groups['guid'].Value.ToUpperInvariant() + '}'
$installer = $null
$database = $null
$summary = $null
try {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.GetType().InvokeMember(
        'OpenDatabase', [Reflection.BindingFlags]::InvokeMethod,
        $null, $installer, @($msiCandidates[0].FullName, 1)
    )
    $summary = $database.GetType().InvokeMember(
        'SummaryInformation', [Reflection.BindingFlags]::GetProperty,
        $null, $database, @(20)
    )
    foreach ($property in @(
        @(9, $packageCode), @(12, $buildTime), @(13, $buildTime)
    )) {
        [void]$summary.GetType().InvokeMember(
            'Property', [Reflection.BindingFlags]::SetProperty,
            $null, $summary, @($property[0], $property[1])
        )
    }
    [void]$summary.GetType().InvokeMember(
        'Persist', [Reflection.BindingFlags]::InvokeMethod,
        $null, $summary, $null
    )
    [void]$database.GetType().InvokeMember(
        'Commit', [Reflection.BindingFlags]::InvokeMethod,
        $null, $database, $null
    )
} finally {
    foreach ($value in @($summary, $database, $installer)) {
        if ($null -ne $value -and [Runtime.InteropServices.Marshal]::IsComObject($value)) {
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($value)
        }
    }
}

[void](New-Item -ItemType Directory -Path $canonicalOutputRoot)
$candidatePath = Join-Path $canonicalOutputRoot 'rustdesk-client.msi'
Copy-Item -LiteralPath $msiCandidates[0].FullName -Destination $candidatePath
$msiSignature = Get-AuthenticodeSignature -LiteralPath $candidatePath
if ($msiSignature.Status -cne 'NotSigned' -or $null -ne $msiSignature.SignerCertificate) {
    throw 'The credential-free packager did not produce one unsigned MSI.'
}
[pscustomobject]@{
    Path = 'rustdesk-client.msi'
    Length = (Get-Item -LiteralPath $candidatePath).Length
    SHA256 = (Get-FileHash -LiteralPath $candidatePath -Algorithm SHA256).Hash.ToLowerInvariant()
    PackageCode = $packageCode
} | Format-List
