param(
    [Parameter(Mandatory = $true)]
    [string]$MsiPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$item = Get-Item -LiteralPath $MsiPath -Force -ErrorAction Stop
if ($item.PSIsContainer -or
    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $item.Extension -ine '.msi' -or $item.Length -lt 512 -or
    $item.Length -gt 768MB) {
    throw 'The MSI compound-file normalizer received an invalid file.'
}

# [MS-CFB] 2.6.2 permits the root storage Modified Time to be all zeroes.
# Windows Installer rewrites that otherwise-unused field with wall-clock time
# when SummaryInformation is committed, which is the final nondeterministic
# byte range in an otherwise reproducible MSI.
$compoundSignature = [byte[]]@(
    0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1
)
$stream = $null
try {
    $stream = [IO.File]::Open(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
    $header = New-Object byte[] 512
    if ($stream.Read($header, 0, $header.Length) -ne $header.Length) {
        throw 'The MSI compound-file header is truncated.'
    }
    for ($index = 0; $index -lt $compoundSignature.Length; $index++) {
        if ($header[$index] -ne $compoundSignature[$index]) {
            throw 'The MSI compound-file signature is invalid.'
        }
    }

    $majorVersion = [BitConverter]::ToUInt16($header, 26)
    $byteOrder = [BitConverter]::ToUInt16($header, 28)
    $sectorShift = [BitConverter]::ToUInt16($header, 30)
    $miniSectorShift = [BitConverter]::ToUInt16($header, 32)
    if ($byteOrder -ne 0xFFFE -or $miniSectorShift -ne 6 -or
        (($majorVersion -eq 3) -and $sectorShift -ne 9) -or
        (($majorVersion -eq 4) -and $sectorShift -ne 12) -or
        ($majorVersion -ne 3 -and $majorVersion -ne 4)) {
        throw 'The MSI compound-file geometry is invalid.'
    }

    [uint32]$firstDirectorySector = [BitConverter]::ToUInt32($header, 48)
    [uint32]$maximumRegularSector = 4294967290
    if ($firstDirectorySector -gt $maximumRegularSector) {
        throw 'The MSI compound-file root directory sector is invalid.'
    }
    [uint64]$sectorSize = [uint64]1 -shl $sectorShift
    [uint64]$rootOffset = ([uint64]$firstDirectorySector + 1) * $sectorSize
    if (($rootOffset + 128) -gt [uint64]$stream.Length) {
        throw 'The MSI compound-file root directory entry is out of bounds.'
    }

    [void]$stream.Seek([int64]$rootOffset, [IO.SeekOrigin]::Begin)
    $rootEntry = New-Object byte[] 128
    if ($stream.Read($rootEntry, 0, $rootEntry.Length) -ne $rootEntry.Length) {
        throw 'The MSI compound-file root directory entry is truncated.'
    }
    $expectedRootName = [Text.Encoding]::Unicode.GetBytes("Root Entry`0")
    if ([BitConverter]::ToUInt16($rootEntry, 64) -ne $expectedRootName.Length -or
        $rootEntry[66] -ne 5) {
        throw 'The MSI compound-file root directory identity is invalid.'
    }
    for ($index = 0; $index -lt $expectedRootName.Length; $index++) {
        if ($rootEntry[$index] -ne $expectedRootName[$index]) {
            throw 'The MSI compound-file root directory name is invalid.'
        }
    }
    if (@($rootEntry[100..107] | Where-Object { $_ -ne 0 }).Count -ne 0) {
        throw 'The MSI compound-file root creation time is invalid.'
    }

    if (@($rootEntry[108..115] | Where-Object { $_ -ne 0 }).Count -ne 0) {
        [void]$stream.Seek([int64]$rootOffset + 108, [IO.SeekOrigin]::Begin)
        $zeroTimestamp = New-Object byte[] 8
        $stream.Write($zeroTimestamp, 0, $zeroTimestamp.Length)
        $stream.Flush($true)
    }

    [void]$stream.Seek([int64]$rootOffset + 108, [IO.SeekOrigin]::Begin)
    $normalizedTimestamp = New-Object byte[] 8
    if ($stream.Read(
        $normalizedTimestamp, 0, $normalizedTimestamp.Length
    ) -ne $normalizedTimestamp.Length -or
        @($normalizedTimestamp | Where-Object { $_ -ne 0 }).Count -ne 0) {
        throw 'The MSI compound-file root modification time was not normalized.'
    }
} finally {
    if ($null -ne $stream) {
        $stream.Dispose()
    }
}

Write-Output 'SIT_MANAGED_MSI_CFB_NORMALIZED=PASS'
