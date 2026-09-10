# RustDesk msi project

Use Visual Studio 2022 to compile this project.

This project is mainly derived from <https://github.com/MediaPortal/MediaPortal-2.git> .

## Steps

1. `python preprocess.py`, see `python preprocess.py -h` for help.
2. Build the .sln solution.

Release automation that requires byte-for-byte repeatability must pass
`--deterministic-seed`, `--version`, `--revision-version`, and `--build-date`.
The stable product seed controls generated GUIDs; version and UTC build date are
then read only from those arguments, so preprocessing does not execute the
unsigned candidate to discover metadata. Without the deterministic seed, the
upstream timestamp and random-GUID behavior is preserved.

The managed release packager also writes the deterministic package code and
summary-information timestamps, then normalizes the compound-file root storage
modification time to zero. [MS-CFB section 2.6.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/026fde6e-143d-41bf-a7da-c08b2130d50e)
permits that root field to be zero; Windows Installer otherwise fills it with
wall-clock time when the summary information is committed. The focused source
CI exercises this normalization and requires it to be fail-closed and
idempotent.

Run `msiexec /i package.msi /l*v install.log` to record the log.

## Usage

1. Put the custom dialog bitmaps in "Resources" directory. The supported bitmaps are `['WixUIBannerBmp', 'WixUIDialogBmp', 'WixUIExclamationIco', 'WixUIInfoIco', 'WixUINewIco', 'WixUIUpIco']`.

## Knowledge

### properties

[wix-toolset-set-custom-action-run-only-on-uninstall](https://www.advancedinstaller.com/versus/wix-toolset/wix-toolset-set-custom-action-run-only-on-uninstall.html)

| Property Name | Install | Uninstall | Change | Repair | Upgrade |
| ------ | ------ | ------ | ------ | ------ | ------ |
| Installed | False | True | True | True | True |
| REINSTALL | False | False | False | True | False |
| UPGRADINGPRODUCTCODE | False | False | False | False | True |
| REMOVE | False | True | False | False | True |

## TODOs

1. Start menu. Uninstall
1. custom options
1. Custom client.
    1. firewall and tcp allow. Outgoing
    1. Show license ?
    1. Do create service. Outgoing.

## Refs

1. [windows-installer-portal](https://learn.microsoft.com/en-us/windows/win32/Msi/windows-installer-portal)
1. [wxs](https://wixtoolset.org/docs/schema/wxs/)
1. [wxs github](https://github.com/wixtoolset/wix)
