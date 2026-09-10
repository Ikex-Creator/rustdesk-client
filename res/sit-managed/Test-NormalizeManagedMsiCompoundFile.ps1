$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$normalizer = Join-Path $PSScriptRoot 'Normalize-ManagedMsiCompoundFile.ps1'
$null = [scriptblock]::Create((Get-Content -LiteralPath $normalizer -Raw))

$testParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
)
$testRoot = Join-Path $testParent (
    'sit-managed-msi-normalizer-test-' + [guid]::NewGuid().ToString('N')
)
[void](New-Item -ItemType Directory -Path $testRoot)

function New-TestCompoundFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [byte[]]$ModifiedTime,

        [byte]$RootObjectType = 5
    )

    $bytes = New-Object byte[] 12288
    [byte[]]$signature = @(
        0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1
    )
    [Array]::Copy($signature, 0, $bytes, 0, $signature.Length)
    [Array]::Copy([BitConverter]::GetBytes([uint16]4), 0, $bytes, 26, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]0xFFFE), 0, $bytes, 28, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]12), 0, $bytes, 30, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]6), 0, $bytes, 32, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint32]1), 0, $bytes, 48, 4)

    $rootOffset = 8192
    $rootName = [Text.Encoding]::Unicode.GetBytes("Root Entry`0")
    [Array]::Copy($rootName, 0, $bytes, $rootOffset, $rootName.Length)
    [Array]::Copy(
        [BitConverter]::GetBytes([uint16]$rootName.Length),
        0, $bytes, $rootOffset + 64, 2
    )
    $bytes[$rootOffset + 66] = $RootObjectType
    [Array]::Copy($ModifiedTime, 0, $bytes, $rootOffset + 108, 8)
    $bytes[$rootOffset + 127] = 0xA5
    [IO.File]::WriteAllBytes($Path, $bytes)
}

try {
    $candidate = Join-Path $testRoot 'candidate.msi'
    New-TestCompoundFile -Path $candidate -ModifiedTime ([byte[]]@(
        0x50, 0x31, 0xF3, 0x6C, 0x71, 0x41, 0xDD, 0x01
    ))
    $before = [IO.File]::ReadAllBytes($candidate)
    $result = (& $normalizer -MsiPath $candidate | Out-String).Trim()
    if ($result -cne 'SIT_MANAGED_MSI_CFB_NORMALIZED=PASS') {
        throw 'The MSI compound-file normalizer did not report success.'
    }
    $after = [IO.File]::ReadAllBytes($candidate)
    for ($index = 0; $index -lt $before.Length; $index++) {
        $expected = if ($index -ge 8300 -and $index -le 8307) {
            [byte]0
        } else {
            $before[$index]
        }
        if ($after[$index] -ne $expected) {
            throw 'The MSI compound-file normalizer changed an unexpected byte.'
        }
    }
    $firstHash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash
    [void](& $normalizer -MsiPath $candidate)
    $secondHash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash
    if ($firstHash -cne $secondHash) {
        throw 'The MSI compound-file normalizer is not idempotent.'
    }

    $invalid = Join-Path $testRoot 'invalid.msi'
    New-TestCompoundFile -Path $invalid -ModifiedTime (New-Object byte[] 8) `
        -RootObjectType 1
    $invalidHash = (Get-FileHash -LiteralPath $invalid -Algorithm SHA256).Hash
    $rejected = $false
    try {
        [void](& $normalizer -MsiPath $invalid)
    } catch {
        $rejected = $true
    }
    if (-not $rejected -or
        (Get-FileHash -LiteralPath $invalid -Algorithm SHA256).Hash -cne $invalidHash) {
        throw 'The MSI compound-file normalizer did not fail closed.'
    }
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        $resolvedTestRoot = (Resolve-Path -LiteralPath $testRoot).Path
        if ((Split-Path -Parent $resolvedTestRoot) -cne $testParent -or
            (Split-Path -Leaf $resolvedTestRoot) -cnotmatch
                '^sit-managed-msi-normalizer-test-[0-9a-f]{32}$') {
            throw 'The MSI compound-file test cleanup target is unsafe.'
        }
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
    }
}

Write-Output 'SIT_MANAGED_MSI_CFB_NORMALIZER_TEST=PASS'
