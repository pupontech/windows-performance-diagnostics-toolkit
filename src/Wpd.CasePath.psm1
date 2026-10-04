Set-StrictMode -Version Latest

function Initialize-WpdCaseDirectoryNative {
    if ($null -ne ('WpdCaseDirectoryNative' -as [type])) { return }
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class WpdCaseDirectoryNative
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateDirectoryW")]
    private static extern bool CreateDirectoryWindows(string path, IntPtr securityAttributes);

    [DllImport("libc", CharSet = CharSet.Ansi, SetLastError = true, EntryPoint = "mkdir")]
    private static extern int CreateDirectoryUnix(string path, uint mode);

    public static int Create(string path)
    {
        if (Environment.OSVersion.Platform == PlatformID.Win32NT)
        {
            return CreateDirectoryWindows(path, IntPtr.Zero) ? 0 : Marshal.GetLastWin32Error();
        }
        return CreateDirectoryUnix(path, 511) == 0 ? 0 : Marshal.GetLastWin32Error();
    }
}
'@
}

function Get-WpdDefaultCaseBaseDirectory {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        return 'C:\WPD-Case'
    }
    return [System.IO.Path]::GetFullPath((Join-Path -Path (Get-Location).Path -ChildPath 'windows-performance-diagnostics'))
}

function Assert-WpdCasePathSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$AllowMissingLeaf
    )

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        if ($fullPath.StartsWith('\\', [System.StringComparison]::OrdinalIgnoreCase) -or $fullPath.StartsWith('//', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Network-share case paths are not permitted.'
        }
        $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
        $relative = $fullPath.Substring($pathRoot.Length)
        $segments = @($relative -split '[\\/]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $current = $pathRoot
        foreach ($segment in $segments) {
            $current = [System.IO.Path]::Combine($current, $segment)
            $isDirectory = [System.IO.Directory]::Exists($current)
            $isFile = [System.IO.File]::Exists($current)
            if (-not $isDirectory -and -not $isFile) {
                if ($AllowMissingLeaf) { continue }
                continue
            }
            if ($isFile -and $current -eq $fullPath) {
                throw "Case path is a file, not a directory: $current"
            }
            try {
                $attributes = [System.IO.File]::GetAttributes($current)
            }
            catch {
                throw "Unable to inspect case path component '$current': $($_.Exception.Message)"
            }
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Case path contains a reparse point: $current"
            }
            if ($isFile -and $current -ne $fullPath) {
                throw "Case path parent is a file: $current"
            }
        }
        return $fullPath
    }
    catch {
        throw "Unsafe case path '$Path': $($_.Exception.Message)"
    }
}

function New-WpdCaseDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$BaseDirectory,
        [DateTime]$TimestampUtc = [DateTime]::UtcNow,
        [string]$RunId = [Guid]::NewGuid().ToString('N')
    )

    if ([string]::IsNullOrWhiteSpace($BaseDirectory)) {
        throw 'BaseDirectory must not be empty.'
    }
    if ([string]::IsNullOrWhiteSpace($RunId) -or $RunId -notmatch '^[A-Za-z0-9-]{1,64}$') {
        throw 'RunId must contain only 1-64 ASCII letters, digits, or hyphens.'
    }

    $basePath = Assert-WpdCasePathSafe -Path $BaseDirectory -AllowMissingLeaf
    if ([System.IO.File]::Exists($basePath)) {
        throw "Case base is a file, not a directory: $basePath"
    }
    try {
        [void][System.IO.Directory]::CreateDirectory($basePath)
    }
    catch {
        throw "Unable to create case base '$basePath': $($_.Exception.Message)"
    }
    $basePath = Assert-WpdCasePathSafe -Path $basePath

    $utc = $TimestampUtc.ToUniversalTime()
    $timestamp = $utc.ToString('yyyyMMddTHHmmssfffZ', [Globalization.CultureInfo]::InvariantCulture)
    $caseName = $timestamp + '-' + $RunId
    $casePath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($basePath, $caseName))
    $baseRoot = [System.IO.Path]::GetPathRoot($basePath)
    if ([string]::Equals($basePath, $baseRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        $expectedParent = $baseRoot
    }
    else {
        $expectedParent = $basePath.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    }
    $actualParent = [System.IO.Path]::GetDirectoryName($casePath)
    $comparison = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
    if (-not [string]::Equals($actualParent, $expectedParent, $comparison)) {
        throw "Generated case path escaped its base directory: $casePath"
    }

    Initialize-WpdCaseDirectoryNative
    $errorCode = [WpdCaseDirectoryNative]::Create($casePath)
    if ($errorCode -ne 0) {
        if (($env:OS -eq 'Windows_NT' -or [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) -and ($errorCode -eq 80 -or $errorCode -eq 183)) {
            throw "Case directory already exists; refusing collision: $casePath"
        }
        if ($env:OS -ne 'Windows_NT' -and $errorCode -eq 17) {
            throw "Case directory already exists; refusing collision: $casePath"
        }
        throw "Unable to reserve case directory '$casePath' (native error $errorCode)."
    }

    $null = Assert-WpdCasePathSafe -Path $casePath
    return $casePath
}

Export-ModuleMember -Function Get-WpdDefaultCaseBaseDirectory, New-WpdCaseDirectory
