# This script parses the configure.ac file and generates the necessary version file.
#
# In order to execute this as part of Visual Studio build, you need to enable RemoteSigned
# in the powershell execution polict.  For both 32-bit and 64-bit Powershell you need to:
#
#	Set-ExecutionPolicy RemoteSigned
#

$configureACFile = $PSScriptRoot + "\..\configure.ac"
$line = cat $configureACFile | Select-String -caseSensitive "-DEV"
$found = $line -match '(\d+).(\d+).(\d)'
IF ($found) 
{
	$major = $matches[1] -as [int]
	$minor = $matches[2] -as [int]
	$micro = $matches[3] -as [int]
	$major *= 256
	$minor *= 64

	$packageVersion = $matches[1] + "." + $matches[2] + "." + $matches[3]
	$packageVersionNum = $major + $minor + $micro
	$packageVersionPlaceholder = "@PACKAGE_VERSION@"
	$packageVersionNumPlaceholder = "@PACKAGE_VERSION_NUM@"

	$destinationFile = $PSScriptRoot + "\..\lib\includes\nghttp2\nghttp2ver.h"
	$sourceFile = $destinationFile + ".in"
	IF (Test-Path $destinationFile) {
		Remove-Item $destinationFile
	}
	(Get-Content $sourceFile) | Foreach-Object { 
		$_ 	-replace $packageVersionPlaceholder, $packageVersion `
			-replace $packageVersionNumPlaceholder, $packageVersionNum
	} | Set-Content $destinationFile
}