$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$workflowPath = Join-Path $repositoryRoot '.github\workflows\sit-managed-release.yml'
$ciPath = Join-Path $repositoryRoot '.github\workflows\sit-managed-client-ci.yml'
$buildPath = Join-Path $PSScriptRoot 'Build-ManagedWindowsClient.ps1'
$packagePath = Join-Path $PSScriptRoot 'Package-ManagedWindowsClient.ps1'
$toolsPath = Join-Path $PSScriptRoot 'Prepare-OfflineSigningTools.ps1'
$evidencePath = Join-Path $PSScriptRoot 'New-ManagedReleaseEvidence.py'
$rustBuildPath = Join-Path $repositoryRoot 'build.rs'
$resourcePath = Join-Path $PSScriptRoot 'managed-windows-resource.rc'
$wixLicensePath = Join-Path $repositoryRoot 'res\msi\WIX-LICENSE.txt'
$workflow = Get-Content -LiteralPath $workflowPath -Raw
$ci = Get-Content -LiteralPath $ciPath -Raw
$build = Get-Content -LiteralPath $buildPath -Raw
$package = Get-Content -LiteralPath $packagePath -Raw
$tools = Get-Content -LiteralPath $toolsPath -Raw
$evidence = Get-Content -LiteralPath $evidencePath -Raw
$rustBuild = Get-Content -LiteralPath $rustBuildPath -Raw
$resource = Get-Content -LiteralPath $resourcePath -Raw

if (-not (Test-Path -LiteralPath $wixLicensePath) -or
    (Get-Item -LiteralPath $wixLicensePath).Length -lt 3000) {
    throw 'The complete WiX Microsoft Reciprocal License is missing.'
}

foreach ($scriptPath in @($buildPath, $packagePath, $toolsPath, $PSCommandPath)) {
    $null = [scriptblock]::Create((Get-Content -LiteralPath $scriptPath -Raw))
}

foreach ($required in @(
    '  workflow_dispatch:',
    "github.repository == 'Ikex-Creator/rustdesk-client'",
    "github.ref == 'refs/heads/release/sit-rustdesk-1.4.9'",
    "github.ref_protected == true",
    "github.workflow_ref == 'Ikex-Creator/rustdesk-client/.github/workflows/sit-managed-release.yml@refs/heads/release/sit-rustdesk-1.4.9'",
    'github.workflow_sha == github.sha',
    'builder: [one, two]',
    'name: unsigned-phase-one-${{ needs.prepare.outputs.generation }}-${{ needs.prepare.outputs.source_commit }}',
    'artifact_contract: rustdesk',
    'phase: phase-one',
    'rustdesk_exe_sha256: ${{ needs.compare_phase_one.outputs.executable_sha256 }}',
    'uses: Ikex-Creator/rustdesk-client/.github/workflows/windows-native-artifact-signer.yml@ca8365fbd940ad82925fb22921d0f0155ddae703',
    'name: signed-phase-one-${{ needs.prepare.outputs.generation }}-${{ needs.prepare.outputs.source_commit }}',
    'packager: [one, two]',
    'name: unsigned-phase-two-${{ needs.prepare.outputs.generation }}-${{ needs.prepare.outputs.source_commit }}',
    'phase: phase-two',
    'rustdesk_msi_sha256: ${{ needs.compare_phase_two.outputs.msi_sha256 }}',
    'name: signed-phase-two-${{ needs.prepare.outputs.generation }}-${{ needs.prepare.outputs.source_commit }}',
    'executable_file_id = ''App.exe''',
    'git ls-files --recurse-submodules -z',
    '--format=posix --sort=name --mtime="@$SOURCE_DATE_EPOCH"',
    'New-ManagedReleaseEvidence.py',
    'name: publishable-managed-release-${{ needs.prepare.outputs.generation }}-${{ needs.prepare.outputs.source_commit }}'
)) {
    if ($workflow.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The managed release workflow lost an exact boundary: $required"
    }
}
if ($ci.IndexOf(
    'python res/sit-managed/test_release_evidence.py',
    [StringComparison]::Ordinal
) -lt 0) {
    throw 'The focused CI workflow no longer runs release-evidence tests.'
}
foreach ($forbidden in @(
    'pull_request:', 'push:', 'schedule:', 'secrets:', 'secrets: inherit',
    'azure/login', 'azure/artifact-signing-action', 'softprops/action-gh-release'
)) {
    if ($workflow.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "The managed release workflow contains a forbidden surface: $forbidden"
    }
}
if ([Regex]::Matches($workflow, '(?m)^\s+id-token:\s+write\s*$').Count -ne 2 -or
    [Regex]::IsMatch($workflow, '(?m)^\s+environment:\s*')) {
    throw 'The public release workflow identity boundary is not exact.'
}
$uses = [Regex]::Matches($workflow, '(?m)^\s+uses:\s+(?<value>\S+)\s*$')
if ($uses.Count -lt 1) {
    throw 'The managed release workflow action inventory is empty.'
}
foreach ($match in $uses) {
    if ($match.Groups['value'].Value -cnotmatch '@[0-9a-f]{40}$') {
        throw "A managed release dependency is not full-commit pinned: $($match.Groups['value'].Value)"
    }
}

foreach ($required in @(
    "`$expectedUpstreamCommit = '6c578292e8ebbbec708b76986ba8c4bc7c509747'",
    "`$sciterCommit = 'f33df075d9eb2f8d252cb88f1b2c8096e56197ed'",
    "`$sciterBytes = 8296448L",
    "`$sciterSha256 = '4d97528e157c55ef1fabe9e37a9697116ab66660d7da6163f90a3a7abf80dd56'",
    "`$env:SOURCE_DATE_EPOCH = `$SourceDateEpoch",
    "`$env:SIT_RUSTDESK_FORK_COMMIT = `$SourceCommit",
    'cargo build --locked --target x86_64-pc-windows-msvc',
    '--features inline,vram,hwcodec --release --bins',
    "`$signature.Status -cne 'NotSigned'"
)) {
    if ($build.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The managed Windows build script lost an exact boundary: $required"
    }
}
if ([Regex]::Matches($build, 'Invoke-WebRequest').Count -ne 1 -or
    [Regex]::Matches($build, 'https://').Count -ne 1) {
    throw 'The managed Windows build download surface drifted.'
}

foreach ($required in @(
    'std::env::var_os("SIT_RUSTDESK_FORK_COMMIT").is_some()',
    'res.set_resource_file("res/sit-managed/managed-windows-resource.rc")',
    'cargo:rerun-if-changed=res/sit-managed/managed-windows-resource.rc',
    'cargo:rerun-if-env-changed=SIT_RUSTDESK_FORK_COMMIT'
)) {
    if ($rustBuild.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The deterministic managed resource boundary drifted: $required"
    }
}
$versionFields = @([Regex]::Matches(
    $resource,
    '(?m)^\s*VALUE\s+"(?<name>[^"]+)",\s+"'
) | ForEach-Object { $_.Groups['name'].Value })
$expectedVersionFields = @(
    'FileDescription', 'FileVersion', 'LegalCopyright',
    'OriginalFilename', 'ProductName', 'ProductVersion'
)
if (($versionFields -join "`n") -cne ($expectedVersionFields -join "`n") -or
    $resource.IndexOf('FILEVERSION 1, 4, 9, 0', [StringComparison]::Ordinal) -lt 0 -or
    $resource.IndexOf('PRODUCTVERSION 1, 4, 9, 0', [StringComparison]::Ordinal) -lt 0 -or
    $resource.IndexOf('1 ICON "res/icon.ico"', [StringComparison]::Ordinal) -lt 0 -or
    $resource.IndexOf('1 24 "res/manifest.xml"', [StringComparison]::Ordinal) -lt 0) {
    throw 'The deterministic managed VERSIONINFO, icon, or manifest contract drifted.'
}

foreach ($required in @(
    'python preprocess.py --arp -d ../../sit-release-dist',
    '--deterministic-seed symplifiedit-rustdesk-x64-v1',
    "'4d97528e157c55ef1fabe9e37a9697116ab66660d7da6163f90a3a7abf80dd56'",
    "'https://dist.nuget.org/win-x86-commandline/v6.11.1/nuget.exe'",
    "'c0ddc9cb0633c4607da7e8028eb4f91248c8b74e45a68b0c79fcfa7d78c2a481'",
    '-p:SITDeterministicBuild=true',
    "`$msiSignature.Status -cne 'NotSigned'"
)) {
    if ($package.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The managed MSI packaging script lost an exact boundary: $required"
    }
}
if ([Regex]::Matches($package, 'Invoke-WebRequest').Count -ne 1 -or
    [Regex]::Matches($package, 'https://dist.nuget.org/').Count -ne 1 -or
    [Regex]::Matches($package, 'https://api.nuget.org/').Count -ne 2) {
    throw 'The managed MSI packaging download surface drifted.'
}

foreach ($required in @(
    'Microsoft.Windows.SDK.BuildTools.10.0.26100.4188.nupkg',
    'Microsoft.ArtifactSigning.Client.1.0.128.nupkg',
    'dotnet-runtime-8.0.30-win-x64.zip',
    "@('buildtools', 192, 22225, 'b9e7b3af121852f804a3aa85dda281b02f9eae6383ff5da8ecdadf4fe6e24586')",
    "@('client', 93, 9345, '709ef91e442f85a9992a7d75a772ea37c44057d47dbf7c8dc3390c0230224610')",
    "@('dotnet', 188, 25438, 'c1f9e26ca15bb2617094caffc4937fd8e3cd25a12592bcfc1a570a086d668211')"
)) {
    if ($tools.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The offline signing-tool bootstrap lost an exact boundary: $required"
    }
}
if ([Regex]::Matches($tools, 'Invoke-WebRequest').Count -ne 1 -or
    [Regex]::Matches($tools, "Uri = 'https://").Count -ne 3) {
    throw 'The offline signing-tool download surface drifted.'
}

foreach ($required in @(
    'WIX_SOURCE_COMMIT = "ce73352b1fa1d4f9cded10a0ee410f2e786bd326"',
    '"licenseConcluded": "MS-RL"',
    'wix_license_path = root / "res" / "msi" / "WIX-LICENSE.txt"',
    '"extractedText": sciter_text'
)) {
    if ($evidence.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The managed release evidence lost a license boundary: $required"
    }
}

Write-Output 'SIT_MANAGED_RELEASE_SOURCE=PASS'
