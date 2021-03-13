## Exchange 0-Day Evaluation
# v5

$erroractionpreference = "silentlycontinue";
$warningpreference = "silentlycontinue";

function err_fnc{
    $em = $_.exception.message;
    $ei = $_.exception.itemname;
    if($ei -ne $null){
        $err = "$em / $ei";
    }
    else{
        $err = "$em";
    }
    write-host -fore red "Cannot Determine ($err)";
}

function enum_vers{
    
    "# Exchange Version"
    $exc = @("language","speech","anti-spam","block","mcafee");
    gci HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | get-itemproperty | ? {$_.displayname -match "Exchange" -and $_.displayname -notmatch ($exc -join '|')} | % {
        "$env:computername | $(($_).displayname) | $(($_).displayversion)"
    }

}

function enum_leverage{

    "`n`t# Leverage of CVEs"
    $cve26858 = new-object collections.generic.list[object];
    write-host -no "`t$env:computername | Checking IoCs for CVE-2021-26858... ";
    try{
        findstr /snip /c:"Download failed and temporary file" "%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog\*.log" | % { 
            $cve26858.add("$_");
        }
        if($(($cve26858).count) -gt 0){
            "Leveraged ($(($cve26858).count))";
        }
        else{
            "Not Leveraged";
        }
    }
    catch{
        err_fnc
    }

    $cve26857 = new-object collections.generic.list[object];
    write-host -no "`t$env:computername | Checking IoCs for CVE-2021-26857... ";
    try{
        get-eventlog -logname Application -source "MSExchange Unified Messaging" -entrytype Error | ? { $_.message -like "*System.InvalidCastException*" } | % {
            $cve26857.add("$_");
        }
        if($(($cve26857).count) -gt 0){
            "Leveraged ($(($cve26857).count))";
        }
        else{
            "Not Leveraged";
        }
    }
    catch{
        err_fnc
    }

    $cve27065 = new-object collections.generic.list[object];
    write-host -no "`t$env:computername | Checking IoCs for CVE-2021-27065... ";
    try{
        select-string -path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log" -pattern 'set-.+VirtualDirectory' | % { if($_ -match "script"){$cve27065="$_"}} | % {
            $cve27065.add("$_");
        }
        if($(($cve27065).count) -gt 0){
            "Leveraged ($(($cve27065).count))";
        }
        else{
            "Not Leveraged";
        }
    }
    catch{
        err_fnc
    }

    $cve26855 = new-object collections.generic.list[object];
    write-host -no "`t$env:computername | Checking IoCs for CVE-2021-26855... ";
    try{
        import-csv -path (gci -recurse -path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy" -filter '*.log').fullname | ? { $_.anchormailbox -like 'ServerInfo~*/*' } | % {
            $cve26855.add("$(($_).datetime)|$(($_).anchormailbox)|$(($_).useragent)|$(($_).routinghint)|$(($_).urlstem)|$(($_).clientipaddress)|$(($_).requestbytes)|$(($_).responsebytes)");
        }
        if($(($cve26855).count) -gt 0){
            "Leveraged ($(($cve26855).count))";
        }
        else{
            "Not Leveraged";
        } 
    }
    catch{
        err_fnc
    }

    if($(($cve26858).count) -gt 0){
        "`n`t# CVE-2021-26858 Artefacts"
        $cve26858 | % { "`t$_" }
    }
    if($(($cve26857).count) -gt 0){
        "`n`t# CVE-2021-26857 Artefacts"
        $cve26857 | % { "`t$_" }
    }
    if($(($cve27065).count) -gt 0){
        "`n`t# CVE-2021-27065 Artefacts"
        $cve27065 | % { "`t$_" }
    }
    if($(($cve26855).count) -gt 0){
        "`n`t# CVE-2021-26855 Artefacts"
        $cve26855 | % { "`t$_" }
    }

}

function enum_iocs{
    
    "`n`t# Potential IoCs / IoEs"
    $bdws_aspx = new-object collections.generic.list[object];
    $bdws_shell = new-object collections.generic.list[object];
    $exc_path = @("c:\programdata\Centrastage");
    $aspx_iocs = @("aspx");
    $aspx_paths = @("C:\inetpub\wwwroot\aspnet_client\");

    write-host -no "`t$env:computername | Checking for potential compromise (ASPX)... ";
    try{
        $aspx_paths | % {
            gci -recurse $_ | ? {$_.name -match ($aspx_iocs -join '|') -and $_.lastwritetime -match "2021"} | % {
                $bdws_aspx.add("$(($_).lastwritetime) | $((get-acl ($_).fullname).owner) | $(($_).fullname) | $((get-filehash ($_).fullname).hash)");
                $bdws_shell.add("# $(($_))`n$((gc $(($_).fullname)))");
            }
        }
        if($(($bdws_aspx).count) -gt 0){
            "Leveraged ($(($bdws_aspx).count))";
        }
        else{
            "Not Leveraged";
        } 
    }
    catch{
        err_fnc
    }

    $bdws_cab = new-object collections.generic.list[object];
    $cab_iocs = @("zip","rar","7z","lsass");
    $cab_paths = @("c:\windows\temp\","c:\root","c:\programdata");

    write-host -no "`t$env:computername | Checking for potential compromise (CAB)... ";
    $cab_paths | ? {$_ -notmatch ($exc_path -join '|')} | % {
        gci -recurse $_ | ? {$_.name -match ($cab_iocs -join '|') -and $_.lastwritetime -match "2021"} | % {
            $bdws_cab.add("$(($_).lastwritetime) | $(($_).fullname)");
        }
    }
    if($(($bdws_cab).count) -gt 0){
        "Leveraged ($(($bdws_cab).count))";
    }
    else{
        "Not Leveraged";
    } 

    if($(($bdws_aspx).count) -gt 0){
        "`n`t# Potential IoCs"
        $bdws_aspx | % { "`t$_" }
    }

    if($(($bdws_cab).count) -gt 0){
        "`n`t# Potential IoEs"
        $bdws_cab | % { "`t$_" }
    }

}

function safety_scan{

    $su = "https://definitionupdates.microsoft.com/download/DefinitionUpdates/VersionedSignatures/AM/1.333.116.0/amd64/";
    $sb = "MSERT.exe";

    sl $env:temp

    write-host -no "Downloading Safety Scanner... "
    try{
        if($os -match "2008" -or $os -match "Windows 7"){
            (new-object system.net.webclient).downloadfile($u,"$((gl).path)\$f")
            "OK!"
        }
        else{
            .{ iwr $u -outfile $f } | out-null
            "OK!"
        }
    }
    catch{
        err_fnc
    }
    
    write-host -no "Executing Safety Scanner... "
    try{
        cmd.exe /c $f /FQ
        "OK!"
    }
    catch{
        err_fnc
    }

    # # while process    
    # write-host -no "Verifying results... "
    # try{
    #     gci c:\windows\debug | ? {$_.lastwritetime -match "2021"} | % {
    #         # gc $(($_).fullname)
    #     }
    #     "OK!"
    # }
    # catch{
    #     err_fnc
    # }

}

function cleanse_aspx{

    $aspx_paths = @("C:\inetpub\wwwroot\aspnet_client\");
    $darc = "c:\windows\debug\exc0";

    try{
        new-item -itemtype directory $darc -force | out-null
    }
    catch{
        "Cannot create directory ($darc)."
    }
    $aspx_paths | % {
        gci $_ | ? { $((get-acl $(($_).fullname)).owner) -match "system" -and $_.lastwritetime -match "2021"} | % {
            write-host -no "Moving $(($_).fullname) to $darc... "
            try{
                move-item "$(($_).fullname)" $darc | out-null
                "OK!"
            }
            catch{
                err_fnc
            }
        }
    }

}

function enum_tasks{

    # legacy; revamp
    function subf{
        [cmdletbinding()]
        param(
            $fref = $sch.getfolder("\")
        )
        if($fref.Path -eq '\'){
            $fref
        }
        if(-not $root){
            $afld = @()
            if(($fld = $fref.getfolders(1))){
                $fld | % {
                    $afld += $_
                    if($_.getfolders(1)) {
                        subf -fref $_
                    }
                }
            }
            $afld
        }
    }
    function trig{
        [cmdletbinding()]
        param(
            $task
        )
        $trigs = ([xml]$task.xml).task.trigs
        if($trigs){
            $trigs | get-member -membertype property | % {
                $trigs.($_.Name)
            }
        }
    }

    try{
        $sch = new-object -comobject 'Schedule.Service'
    }
    catch{
        return
    }

    $sch.connect($env:computername)
    $afld = subf

    foreach ($fld in $afld){
        if(($tasks = $fld.GetTasks(1))){
        #  server | author | userid | description | trigger | name | path | state | enabled | lastruntime | lasttaskresult | missedruns | nextruntime
        $tasks | ? { $(([xml]$_.xml).task.registrationinfo.author) -ne $null -and $(([xml]$_.xml).task.registrationinfo.author) -notmatch "SystemRoot"} | % {
            "Task^$srv^$(([xml]$_.xml).task.registrationinfo.author)^$(([xml]$_.xml).task.principals.principal.userid)^$(([xml]$_.xml).task.tegistrationinfo.description)^$($_.name)^$($_.path)^$($_.State)^$($_.enabled)^$($_.lastruntime)^$($_.lasttaskresult)^$($_.numberofmissedruns)^$($_.nextruntime)^$(trig -task $_)"
            }
        }
    }

}

enum_vers
enum_leverage
enum_iocs
