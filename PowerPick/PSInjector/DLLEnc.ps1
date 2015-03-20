function Invoke-DllEncode
{
Param(
	[Parameter(Position = 0)]
	[String]
	$InputPath,
	[Parameter(Position = 1)]
	[String]
	$OutputPath=$InputPath+".enc"
)
	$Content = Get-Content -Path $InputPath -Encoding Byte
	$Base64 = [System.Convert]::ToBase64String($Content)
	$Base64 | Out-File $OutputPath
}