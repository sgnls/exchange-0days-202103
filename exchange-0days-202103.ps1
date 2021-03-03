write-host -no "$env:computername | Checking IoCs for CVE-2021-26858... "
if($(findstr /snip /c:”Download failed and temporary file” “%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog\*.log”)){
    $cve26858="$_";
    "Leveraged";
}
else{
    "Not Leveraged";
}

write-host -no "$env:computername | Checking IoCs for CVE-2021-26857... "
if($(get-eventlog -logname Application -source “MSExchange Unified Messaging” -entrytype Error | ? { $_.message -like "*System.InvalidCastException*" }))
    $cvecve26858="$_";
    "Leveraged";
}
else{
    "Not Leveraged";
}

write-host -no "$env:computername | Checking IoCs for CVE-2021-27065... "
select-string -path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log" -pattern ‘set-.+VirtualDirectory’ | % { if($_ -match "script"){$cve27065="$_"}}
if($cve27065){
    "Leveraged";
}
else{
    "Not Leveraged";
}

$cve26855 = new-object collections.generic.list[object]
write-host -no "$env:computername | Checking IoCs for CVE-2021-26855... "
if($(import-csv -path (gci -recurse -path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy" -filter ‘*.log’).fullname | ? { $_.AnchorMailbox -like ‘ServerInfo~*/*’ } | % {$cve26855.add("$(($_).datetime)|$(($_).anchormailbox)|$(($_).urlstem)|$(($_).clientipaddress)|$(($_).requestbytes)|$(($_).responsebytes)")})){
    "Leveraged";
}
else{
    "Not Leveraged";
} 

if($cve26858){
	"# CVE-2021-26858 Artifacts"
	$cve26858
}
if($cve26857){
	"# CVE-2021-26857 Artifacts"
	$cve26857
}
if($cve27065){
	"# CVE-2021-27065 Artifacts"
	$cve27065
}
if($cve26855){
	"# CVE-2021-26855 Artifacts"
	$cve26855
}
