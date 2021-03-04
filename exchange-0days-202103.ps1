
$cve26858 = new-object collections.generic.list[object]
write-host -no "$env:computername | Checking IoCs for CVE-2021-26858... "
findstr /snip /c:”Download failed and temporary file” “%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog\*.log” | % { 
    $cve26858.add("$_")
}
if(($cve26858).count -gt 0){
    "Leveraged";
}
else{
    "Not Leveraged";
}

$cve26857 = new-object collections.generic.list[object]
write-host -no "$env:computername | Checking IoCs for CVE-2021-26857... "
get-eventlog -logname Application -source "MSExchange Unified Messaging" -entrytype Error | ? { $_.message -like "*System.InvalidCastException*" } | % {
    $cve26857.add("$_")
}
if(($cve26857).count -gt 0){
    "Leveraged";
}
else{
    "Not Leveraged";
}

$cve27065 = new-object collections.generic.list[object]
write-host -no "$env:computername | Checking IoCs for CVE-2021-27065... "
select-string -path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log" -pattern ‘set-.+VirtualDirectory’ | % { if($_ -match "script"){$cve27065="$_"}} | % {
    $cve27065.add("$_")
}
if(($cve27065).count -gt 0){
    "Leveraged";
}
else{
    "Not Leveraged";
}

$cve26855 = new-object collections.generic.list[object]
write-host -no "$env:computername | Checking IoCs for CVE-2021-26855... "
import-csv -path (gci -recurse -path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy" -filter ‘*.log’).fullname | ? { $_.AnchorMailbox -like ‘ServerInfo~*/*’ } | % {
    $cve26855.add("$(($_).datetime)|$(($_).anchormailbox)|$(($_).urlstem)|$(($_).clientipaddress)|$(($_).requestbytes)|$(($_).responsebytes)")
}
if(($cve26855).count -gt 0){
    "Leveraged";
}
else{
    "Not Leveraged";
} 

if(($cve26858).count -gt 0){
	"# CVE-2021-26858 Artefacts"
	$cve26858
}
if(($cve26857).count -gt 0){
	"# CVE-2021-26857 Artefacts"
	$cve26857
}
if(($cve27065).count -gt 0){
	"# CVE-2021-27065 Artefacts"
	$cve27065
}
if(($cve26855).count -gt 0){
	"# CVE-2021-26855 Artefacts"
	$cve26855
}
