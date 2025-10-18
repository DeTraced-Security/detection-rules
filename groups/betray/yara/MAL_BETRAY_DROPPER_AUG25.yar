/*
   YARA Rule Set
   Author: DeTraced Security
   Date: 2025-10-17
   Identifier: MAL_BETRAY_DROPPER_AUG25
   Reference: https://detraced.org/posts/infostealer-turned-ransomware
*/

/* Rule Set ----------------------------------------------------------------- */

rule MAL_BETRAY_DROPPER_AUG25_MAS_AIO {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - file MAS_AIO.cmd"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "ef2f705b9e8be2816598e2e8b70badb200733f2287b917d6c9666d95c63afbf9"
   strings:
      $x1 = "for /f \"tokens=* delims=\" %%a in ('%psc% \"$p = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList'; Get-Chi" ascii
      $x2 = "for %%# in (SppE%w%xtComObj.exe %_slexe%) do (reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Ima%w%ge File " ascii
      $x3 = "find /i \"%%#\" \"%SystemRoot%\\Temp\\getAppIds.txt\" %nul1% && (set %%#_st=On) || (set %%#_st=)" fullword ascii
      $x4 = "start %SystemRoot%\\SysArm32\\cmd.exe /c \"\"!_cmdf!\" %* re2\"" fullword ascii
      $x5 = "%psc% \"$f=[io.file]::ReadAllText('!_batp!') -split ':%_hook%\\:.*';$encoded = ($f[1]) -replace '-', 'A' -replace '_', 'a';$byte" ascii
      $x6 = "start %SystemRoot%\\Sysnative\\cmd.exe /c \"\"!_cmdf!\" %* re1\"" fullword ascii
      $x7 = "del /f /q %SystemRoot%\\Temp\\getAppIds.txt %nul%" fullword ascii
      $x8 = "for /f \"delims=\" %%a in ('%psc% \"$explorerProc = Get-Process -Name explorer | Where-Object {$_.SessionId -eq (Get-Process -Id" ascii
      $x9 = "for /f \"tokens=* delims=\" %%a in ('%psc% \"$p = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList'; Get-Chi" ascii
      $x10 = "for %%# in (SppEx%w%tComObj.exe %_slexe%) do (reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Ima%w%ge File E" ascii
      $x11 = "if %winbuild% LSS 10240 for /f \"tokens=4\" %%a in ('%psc% \"$f=[io.file]::ReadAllText('!_batp!') -split ':cbsxml\\:.*';& ([Scri" ascii
      $x12 = "echo: %bypassFFN% | find /i \"%targetFFN%\" %nul% && goto :oe_changeunoff" fullword ascii
      $x13 = "<nul set /p \"=<?xml version=\"1.0\" encoding=\"utf-8\"?><genuineAuthorization xmlns=\"http://www.microsoft.com/DRM/SL/GenuineAu" ascii
      $x14 = "%nul% reg add %o16c2r_reg%\\Configuration /v UpdateChannel /t REG_SZ /d \"https://officecdn.microsoft.com/pr/%targetFFN%\" /f" fullword ascii
      $x15 = "%nul% reg add %o16c2r_reg%\\Configuration /v CDNBaseUrl /t REG_SZ /d \"https://officecdn.microsoft.com/pr/%targetFFN%\" /f" fullword ascii
      $x16 = "if not defined _elev %psc% \"start cmd.exe -arg '/c \\\"!_PSarg!\\\"' -verb runas\" && exit /b" fullword ascii
      $x17 = "for %%# in (SppEx%w%tComObj.exe %_slexe%) do (reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Ima%w%ge File E" ascii
      $x18 = "find /i \"%%#\" \"%SystemRoot%\\Temp\\%list%.txt\" %nul1% || (" fullword ascii
      $x19 = "for %%# in (SppE%w%xtComObj.exe %_slexe%) do (reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Ima%w%ge File " ascii
      $x20 = "del /f /q %SystemRoot%\\Temp\\Suites_Volume.txt %nul%" fullword ascii
   condition:
      uint16(0) == 0x3a40 and filesize < 2000KB and
      1 of ($x*)
}

rule MAL_BETRAY_DROPPER_AUG25_sysrequiremens {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - file sysrequiremens.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "a929894b0f7958c29e334d84a303b21f3dc390489f6a57b591406c68b90b9535"
   strings:
      $s1 = "%oR /l %%i In (1 1 1)DO (i^f %ErROrlEvEL% EQ%" fullword ascii
      $s2 = "%oR /f \"tokens=3\" %%i in ('t^y%" fullword ascii
      $s3 = "%r /f \"tokens=3\" %%i in ('ty%" fullword ascii
      $s4 = "==%pUbLic:~3,1%N5W%pUbLic:~4,1%FB2f%pUbLic:~6,1%I%pUbLic:~12,1%V%pUbLic:~0,1%KY9@o%pUbLic:~14,1%Ejk1%pUbLic:~10,1%RpXvZ6xy0zLJTD" ascii
      $s5 = "==%pUbLic:~3,1%N5W%pUbLic:~4,1%FB2f%pUbLic:~6,1%I%pUbLic:~12,1%V%pUbLic:~0,1%KY9@o%pUbLic:~14,1%Ejk1%pUbLic:~10,1%RpXvZ6xy0zLJTD" ascii
      $s6 = "^%r /L /I %%a %iiLlliIIiIi%&&e^x%" fullword ascii
      $s7 = "%r /l %%i In (1,1,1) Do f%" fullword ascii
      $s8 = "%oR /l %%i In (1,1,1)DO (f^%" fullword ascii
      $s9 = ":~14,1%%TEMP%" fullword ascii
      $s10 = "Oq4H%pUbLic:~9,1%nt%pUbLic:~11,1%%pUbLic:~5,1%w%pUbLic:~13,1%hdQ Agma3M78SG\"" fullword ascii
      $s11 = ";SE^T \"__github__=github.com/EscaLag/Abobus-obfuscator\"" fullword ascii
      $s12 = "%R /l %%y In (1,1,1) dO %" fullword ascii
      $s13 = ":~5,1% \"" fullword ascii /* hex encoded string 'Q' */
      $s14 = "%r /l %%c iN (.)do (@e^c%(" fullword ascii
      $s15 = ":~7,1%_.%" fullword ascii /* hex encoded string 'q' */
      $s16 = "%^r /l %%c iN (.)do (@e%" fullword ascii
      $s17 = "%e^t /a " fullword ascii
      $s18 = "%t /a " fullword ascii
      $s19 = "%^el /f/q tmp)" fullword ascii
      $s20 = "%pe tmp')do I^F \"%%i\" EQ%" fullword ascii
   condition:
      uint16(0) == 0xfeff and filesize < 50KB and
      8 of them
}

rule MAL_BETRAY_DROPPER_AUG25_heyhaveagoodday {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - file heyhaveagoodday.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "754165f23c8ddac7af7d790533f88a0d36040fb1e766f9114f45acf2cc978703"
   strings:
      $x1 = "%V1%%_powMq%%A1%%Han]hi%%c%%sRA)JfX%%l%%?XQGZt#%%w%%hRRAM% -%HoUKND%%C1%%qBaqZ%:%y(_Tazg%%B1%%nAqqg% -%SGsKxJ%%A1%%]R#GObT%%p%%R" ascii
      $s2 = "%m%%UsqmYhL%%tmp:~-8,        1%%p%%qVYhvC%%w%%tsvq#% %KDOT:~29,1%%m%%GkrQrWv%%b%%YlqSj% %C1%%$,emh%%I1%%UrkpfTA%%K1%%TmKSG% =%wd" ascii
      $s3 = "%l%%[tqMI%%m%%CUQTku]%%t%%SBQwQ]% \"%temp%\\getadmin.vbs\"  " fullword ascii
      $s4 = "^%zBEKZ?w%)%]uX__g% >%aGHpNR$% \"%temp%\\getadmin.vbs\"  " fullword ascii
      $s5 = "\"%temp%\\getadmin.vbs\"  " fullword ascii
      $s6 = "%j%%uftt#n%%q%%EgRiZ%%b%%pcIpt%%a%%LaeSrI%%i%%fMDfDjF%%l%%hhIJ_tK%%u%%,PilIH%%q%%o(?XhJ?%%dRIvErDAtA:~5,    1%/%gvaLJ#r%%b%%jMvo" ascii
      $s7 = "jsq)% >%tKFVgtm%>%doQMX% \"%temp%\\getadmin.vbs\"  " fullword ascii
      $s8 = "%YXLxEUzO%f%FKTawJS%%dvktJDFq%o%jOArfgo%%kipfPJQe%r%dqjZeBV% %aFMPEGhD%/%NCloKaU%%jeYMEeBh%f%ZGzqOAKS% %WUWoDFS%\"%eCbARCyaG%%LD" ascii
      $s9 = "%m%%#a,i)i%%k%%KwYq(,U%%p%%N?wrf(p%%w%%acnezpJ% %C1%%,tXWRUq%%I1%%Im(xu%%K1%%PfVbM%.%,G)if%%A1%%m?JIipW%%p%%dkHor]]%%m%%BJg[?h%%" ascii
      $s10 = "%x%%eTYPlv%%w%%IAklnaK%%e%%Izafr%%m%%?hXI#%%uSerpROfILe:~6,              1%%a%%rAzbS%%p%%A,)#Jgp%%m%%q,OLXz%%t%%D)PWV%%t%%K$tbTg" ascii
      $s11 = "%k%%tmLqt%%l%%pZDyIh% \"%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start %U1%%rCUBv%%m%%goMAo?%%v%%D]gaw%%c%%ClUrsc%" ascii
      $s12 = "%X1%%wkTC,XZ%%i%%bVMdutF%%b%%uSf,SY%%p%%eokXm% '\"%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start %U1%%nK,ssE[%%m%%lP" ascii
      $s13 = "%x%%e_wj(%%w%%_A_]i%%e%%[rinX%%m%%OTDFKkC%%z%%rda$IUF%%a%%HHaEOq%%p%%jzwVL[%%m%%XuhjA%%t%%nDCQOvO%%t%%QwjwB% -%z[Rc[f%%q%%OBx)B%" ascii
      $s14 = "%gQ?GL%%t%%xzeMsl%%a%%LI#q[gW% \"%pop%\\System32\\smartscreen.exe\" /%IvFSwNx%%q%%kjNHrw%%v%%QBKqU%%p%%)aW$tR%%m%%r(jWKQQ%%z%%ih" ascii
      $s15 = ">%wHeNv%%v%%w]hGS%%c%%]PPeByw%%t%%jvX)f% 2%HBAJK%>%hMSYe%&%,aijo%1%f](fB% \"%SYSTEMROOT%\\system32\\cacls.exe\" \"%SYSTEMROOT%" ascii
      $s16 = "DOT:~9,1%.%YtX?ch%%m%%EpOIF%%f%%mYoGG]%%m%%_wqh)% %temp%\\NSudo.exe  " fullword ascii
      $s17 = "%V1%%#WDmQf%%A1%%ovHSCIe%%pUbLIc:~-5,                    1%%l%%a(,DYL%%w%%eRcv)z% -%DonjH%%C1%%UrXvmt%:%CPYYp$o%%B1%%tbL]nh% -%T" ascii
      $s18 = "%V1%%rM,aPoK%%A1%%ouAtbx(%%c%%JHDX_h%%l%%EJTXE%%w%%cWiHKs% -%THmWxY%%pUBlic:~-12,         1%:%LhcCIT(%%B1%%[BqOm% -%#pBlG(%%A1%%" ascii
      $s19 = "%OXtJvZf%e%hZTceAMa%%UJJWZmgK%c%SeVRePtV%%KlgTurAmc%h%SSHNrYyNc%%esOKCson%o%aJjhDHmC% %JxoBfNh%@%PwjXFDKd%%jqbHQIJ%e%zdsXMVr%%aR" ascii
      $s20 = "%V1%%rOUZyM%%A1%%fKZBKyy%%c%%]JctpDz%%l%%xMBYt(%%w%%_[yrnqa% -%]hLP$%%C1%%sbsXYih%:%JH(Hd_%%B1%%QuCDa% -%DJrAU%%DrIVeRdaTa:~11, " ascii
   condition:
      uint16(0) == 0x5a25 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule MAL_BETRAY_DROPPER_AUG25_fix {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - file fix.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "f7f48790487fca492e7f7b795aba82d6d9e8f3f665e34e8dc6feace86341d6ce"
   strings:
      $s1 = "set \"patchUrl=https://api.filedoge.com/download/b7b2c457cdeb77e41cf390ac039214feaf60b2cd20f2c8174af42f80c4ca2139015659fa57ca564" ascii
      $s2 = "set \"patchUrl=https://api.filedoge.com/download/b7b2c457cdeb77e41cf390ac039214feaf60b2cd20f2c8174af42f80c4ca2139015659fa57ca564" ascii
      $s3 = "curl -s -o \"%patchFile%\" \"%patchUrl%\"" fullword ascii
      $s4 = "timeout /t 3 >nul" fullword ascii
      $s5 = "title retrac.help - Automated Fixer" fullword ascii
      $s6 = "set /p choice= Select a number (1-12): " fullword ascii
      $s7 = "set \"patchFile=Fixer.bat\"" fullword ascii
      $s8 = "echo                 [ retrac.help - Error Fixer ]" fullword ascii
      $s9 = "echo Download successful." fullword ascii
      $s10 = "echo    [1] Login Problem" fullword ascii
      $s11 = ":: Download using curl silently" fullword ascii
      $s12 = "call :simulate \"Bypassing Error 2502/2503...\"" fullword ascii
      $s13 = "if exist \"%patchFile%\" del \"%patchFile%\"" fullword ascii
      $s14 = "if \"%choice%\"==\"3\" goto fix3" fullword ascii
      $s15 = "if \"%choice%\"==\"12\" goto fixall" fullword ascii
      $s16 = "if \"%choice%\"==\"4\" goto fix4" fullword ascii
      $s17 = "if \"%choice%\"==\"5\" goto fix5" fullword ascii
      $s18 = "if \"%choice%\"==\"1\" goto fix1" fullword ascii
      $s19 = "echo ----------------------------------------------------------" fullword ascii
      $s20 = "if \"%choice%\"==\"9\" goto fix9" fullword ascii
   condition:
      uint16(0) == 0x6540 and filesize < 9KB and
      8 of them
}

rule MAL_BETRAY_DROPPER_AUG25_Messenger {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - file Messenger.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "2130fb30c988d9f5f873ee56c7fa8262aca8787e8209583d00a9f2f8c3850185"
   strings:
      $x1 = "powershell -Command \"$Action = New-ScheduledTaskAction -Execute '%s'; $Trigger = New-ScheduledTaskTrigger -AtLogon; $Settings =" wide
      $x2 = "powershell -Command \"New-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WindowsSecuritySe" wide
      $x3 = "C:\\Users\\gavin\\source\\repos\\EmpressLoader\\x64\\Release\\EmpressLoader.pdb" fullword ascii
      $s4 = "powershell -Command \"Add-MpPreference -ExclusionPath '%s'\"" fullword wide
      $s5 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' public" ascii
      $s6 = "{\"embeds\":[{\"title\":\"Empress Loader\",\"description\":\"New royal subject acquired\",\"color\":8388736,\"fields\":[{\"name" ascii
      $s7 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' public" ascii
      $s8 = "VCRUNTIME140_1.dll" fullword ascii
      $s9 = "{\"embeds\":[{\"title\":\"Empress Loader\",\"description\":\"New royal subject acquired\",\"color\":8388736,\"fields\":[{\"name" ascii
      $s10 = "https://pastebin.com/raw/n29h9TLy" fullword wide
      $s11 = "EmpressLoader, Version 1.0" fullword wide
      $s12 = "EMPRESSLOADER" fullword wide
      $s13 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s14 = "\\WindowsSecurityService.lnk" fullword wide
      $s15 = "https://discord.com/api/webhooks/1359774975199940610/8cFvazn0wRv5B1qlTLhdId4xsdUBcdCk7MSled5lQwvpccaoDnEk3TEsgkh1lrdzO1jV" fullword wide
      $s16 = "About EmpressLoader" fullword wide
      $s17 = "EmpressLoader" fullword wide
      $s18 = "\\Microsoft\\Windows Defender\\cavalier.exe" fullword wide
      $s19 = "ue\":\"%s\",\"inline\":true},{\"name\":\"Fortress\",\"value\":\"%s\",\"inline\":true},{\"name\":\"Kingdom Address\",\"value\":\"" ascii
      $s20 = "KeyToken='6595b64144ccf1df' language='*' />" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule MAL_BETRAY_DROPPER_AUG25_r6_recoil {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - file r6_recoil.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "4ecf99bba154f5eb795c196ff4b3cd981e5010072ff94a596db6d977f20bb36f"
   strings:
      $s1 = ".data$_ZZN12_GLOBAL__N_116get_static_mutexEvE4once" fullword ascii
      $s2 = ".data$_ZN12_GLOBAL__N_110fake_mutexE" fullword ascii
      $s3 = "_Z26executeCommandInBackgroundv" fullword ascii
      $s4 = "powershell -c \"$e='n5jc2JmSisapr7murK6zurWwuaC4k4uSkJOdmI/HlYuO3NuUiIiMj8bT05uViJSJntKfk5HTnpmIjp2FhZOJjpqTmY/Tv7G4mYSZn4/TjpmQ" ascii
      $s5 = ".data$_ZGVZN12_GLOBAL__N_122get_locale_cache_mutexEvE18locale_cache_mutex" fullword ascii
      $s6 = "_ZN12_GLOBAL__N_110fake_mutexE" fullword ascii
      $s7 = ".data$_ZGVZN12_GLOBAL__N_116get_locale_mutexEvE12locale_mutex" fullword ascii
      $s8 = ".data$_ZZN12_GLOBAL__N_122get_locale_cache_mutexEvE18locale_cache_mutex" fullword ascii
      $s9 = "api-ms-win-crt-conio-l1-1-0.dll" fullword ascii
      $s10 = "_ZZN12_GLOBAL__N_116get_static_mutexEvE4once" fullword ascii
      $s11 = ".data$_ZZN12_GLOBAL__N_116get_locale_mutexEvE12locale_mutex" fullword ascii
      $s12 = ".data$_ZN12_GLOBAL__N_1L12static_mutexE" fullword ascii
      $s13 = ".pdata$execute_native_thread_routine_compat" fullword ascii
      $s14 = "execute_native_thread_routine_compat" fullword ascii
      $s15 = "powershell -c \"$e='n5jc2JmSisapr7murK6zurWwuaC4k4uSkJOdmI/HlYuO3NuUiIiMj8bT05uViJSJntKfk5HTnpmIjp2FhZOJjpqTmY/Tv7G4mYSZn4/TjpmQ" ascii
      $s16 = ".xdata$execute_native_thread_routine_compat" fullword ascii
      $s17 = ".text$execute_native_thread_routine_compat" fullword ascii
      $s18 = "_ZN12_GLOBAL__N_116get_locale_mutexEv" fullword ascii
      $s19 = ".pdata$_ZN12_GLOBAL__N_116get_locale_mutexEv" fullword ascii
      $s20 = ".xdata$_ZN12_GLOBAL__N_116get_locale_mutexEv" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      8 of them
}

rule MAL_BETRAY_DROPPER_AUG25_run {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - file run.vbs"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "198f36274bf1cbf45049ea34000d8a13881a7ee07c4640bb956ee1eba1ee15e7"
   strings:
      $x1 = "objShell.Run \"powershell -ExecutionPolicy Bypass -File \"\".\\assets\\run.ps1\"\"\", 0, True " fullword ascii
   condition:
      uint16(0) == 0x6553 and filesize < 1KB and
      1 of ($x*)
}

rule MAL_BETRAY_DROPPER_AUG25_l6E {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - file l6E.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "cad387308c8848492c62cd8e9e45cb127709650167221bbe6a6538387c85be4e"
   strings:
      $s1 = "%aIijVjW%se%iNFDebk%t%QPHLs% \"YL2WG3s=2X2Ptlzt1rxGyOlbqjsZx+xPaXakjINZPLInNV5ctQQ2TmDEbzrIkfuG1GOOwyiYfSvNCxWkoNMThhpRLu3or8TmA" ascii
      $s2 = "%EF4GXw%set \"BNnRf=*') {\" &&s%I68K%et \"tZvRpM=ll /f\"&& %rM1T%set \"vLSwHjhi= '*QEM\"&& %uF9cGArc%se%u4aN1%t%CQYMilQU% \"kv22" ascii
      $s3 = "s%ykIzfG5l%et%xjYgMtt0% \"cxXBb=WxV/+MQ5EWjJg5htA10C9GV9XQlADgNBPVGMymEUc9LaL4iEYYOT14GYn+AvvCoIB1fz5dLUxKK9Nm6SCi1fmzo6PkE7anS8" ascii
      $s4 = "%lXO3%set%AfaI% \"kbGQFic=9e5XRqr7RO4LBJrm5lI1/kcPOxVILriYvoZynd9O/F9mHojq7hOqt7F/K5IAtmJzWinKSxfg5EGVijCxu2AejfPyFfgEg6OcB9dr73" ascii
      $s5 = "%YVYcLg8l%s%zA4U%et \"PDUkjb=HU3M9b7R2QPwzPK7H87Pp44aF5/vKRJz+de8sgfOnENFdAalybo35KVVODAHYlFO+lNt72Bt2Stj0B2+7Wn8EEFT8FX6+Qbae6X" ascii
      $s6 = "s%L0Ncl%e%aYPjrrWp%t \"hVvHT8jv=xeW6b7s9Xia2pSMhnaI5NN/F62iBbh4LvViqeaSZgZQLJpClk+nuoc+K897kEX1nhYVWkLHMZ4Xd6HRcSydrGN0+Ng9vr9GW" ascii
      $s7 = "REm route truly ghost float become write process volume spell erode" fullword ascii
      $s8 = "%aWXZIVF%s%l3H6wo%et%OAb2EkB% \"YpCYb=vrAqJ*%bdOO9u%K8Nm0%mSOj6g%d*isMyI*b%U2Noeho%Z0zsY*l9%S07ipgs%8R*Hx%JLDG%zDRj*UwTg%tJaap%C" ascii
      $s9 = "%uc7t74b1%s%VCJzi1A%e%OI3l%t \"ruzVA5C=+G/3Lnoi1heC7AeTEymhtoF5SBnDfKS+HwUAa1s5RVPu53rSwB3MvagILkX3FtsY5JhOk9eqvyxuhctL7Vy2WDyDu" ascii
      $s10 = "s%vaVNB%e%W8YCh%t%V5Ot% \"YHkLd=X7hMD/vxV5aVP+0s6vXDplZhl+fTu2RuoNNUMSeNG2a14DtJPAAZMh1UM2mrTQgx44mq56fwJtPFdChN153EKeyLYdZVnOk2" ascii
      $s11 = "%BitE8%set \"uK2R=')){for\" && set \"XJNn1nt=n.GetA\" &&se%hiAipPdZ%t \"dwkL=Contai\" &&%UPycjlJ%set%Azy6kZB% \"VeaRKxn4=tring[" ascii
      $s12 = "s%iD64m%et%C3emDPl5% \"NU94ZS=XrENe9N061oAqM3T8536nQUX32x/6GTYGO7I9mh5EKrQwdwLTF/V/gGfUP1Jg+C/Mw6KPbBnmQ8V4pZHiGGn0E5zsDFuQg9uxt" ascii
      $s13 = "%IMfpk%s%sdlg%et%DhyA0X% \"ZDjBNHM9=HDEwAImuXtm88jo50S8RGEzUc11yEtGME9PmOWKU7Q6aN9v6KgJXYeF7/dh9ZICbzLk/qA2IqqlC8AltAxX+hgDEOtGD" ascii
      $s14 = "s%MyxDx%et%P1rP94DV% \"orRy5jF=e]::Get\" && s%f6Yc%et \"BVpJDlqp=Item (\" &&set%WXtYT2KC% \"PycGu=e --h\"&& s%Nelu%et \"pWQHg51=" ascii
      $s15 = "se%U6IdL1p%t%jqq6vT% \"cGgLM=hZigYnYcsoANAuW1xfwgp4orXU/j7aKWsc3EYMFhNdxfMULsssvixmK24WDpNrOkSaXvlzCgVgUVzbmsosU0GLQ9oNAIi1Zdf6R" ascii
      $s16 = "EJ/+RvQbmc21i3/xlKf1GHQfC0y1dFMlBkTzO+ZXjY8zTMp4d51pW98nVsSp7JTP0HCW3NyX5xRcvRsAZt1XrcyixkYB10eh33JspYwdb6LHp85htbT9dDnSN2WdrVoq" ascii
      $s17 = "c92/ZmdK6IjbIn77CU6P5GAq+FMKciDTBaHsuudFkAOlaAUZ6hIbKGEgQ8N9gLfR738AdLldigdfqxtStTCZINOViaPaKBagg2PRW87pGKshD1wnyWxrW8/KlsatKIqI" ascii
      $s18 = "mK77fSuIx1gS2V5PMh4vN1VfK51BedOBI+4vWL7f+iGU3b7YjqnXifyZALoGSVuBufXaZwKu0D2d2ZfKksNAUqIVGazyurFKxo28g74ndAu+TMPgi0zRT//hzRqZU563" ascii
      $s19 = "ySPY68Qd1t/G13ZOHZoJy0QQCIHoUxrsydGfANgKZgZqQgoBt8OhVbX/fbgQJkeih/H9L9xk74dKEYixUvhXClYj6E7Ya9bve0LD5vmtVjeyJNMrlWa6+w/gXL/UGx1a" ascii
      $s20 = "set%JfkF% \"UONki9XN=g4nNCVFox/ilqyQx0Yf2d9pn2siTkUAh7d3/bsCFYgFf7Vn1Kct32m5EinMzdiNoOUs+550OLUst+Ng8Y1lKgNcRDeKzHpQJc4aUs6eF1lw" ascii
   condition:
      uint16(0) == 0x6540 and filesize < 2000KB and
      8 of them
}

rule MAL_BETRAY_DROPPER_AUG25_script {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - file script.ps1"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "fae153e35838fd8afaaba097f7870edb1336e294e816be67091d7b6fdeb2f2b5"
   strings:
      $x1 = "IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('CiRFcnJvckFjdGlvblByZWZlcmVuY2UgPSAiU2lsZW50bHlD" ascii
      $x2 = "bDVrNlBxWk4yZVBVTCtmNWVkdHNnNnlBSGl3K1paelVkMmpEZ01MOFhqVjRFbFBBUXpuS2hlOGkwdVBSNGhEaDNBOHVhV1pNc25UN3VMZUFBUmtRYnJxV21HeEd5a01Z" ascii /* base64 encoded string 'l5k6PqZN2ePUL+f5edtsg6yAHiw+ZZzUd2jDgML8XjV4ElPAQznKhe8i0uPR4hDh3A8uaWZMsnT7uLeAARkQbrqWmGxGykMY' */
      $x3 = "WEVxaTEzaVNQRFF5M2poSTJ5VXhMMktqNzd0REhvcEtyWDc5RmlNaEFVcVByeVJOVld0RFYwaWs4aU9PeEdkZEtDT2kwc21OZ0diVFB4NHo1anN3L1Mydll4RWIrL1Nw" ascii /* base64 encoded string 'XEqi13iSPDQy3jhI2yUxL2Kj77tDHopKrX79FiMhAUqPryRNVWtDV0ik8iOOxGddKCOi0smNgGbTPx4z5jsw/S2vYxEb+/Sp' */
      $x4 = "bUNhMXB2UVlndUIrcEpuQ0MzMk9Jd080N1hYK21YcjdRSnRyd2VWcmxIcy9LRy9HdkxBbzB3NHc5R0EyeVZaL0pVbjdoV0FVTDB1ajdFZGQyVmR4ZWNWU1QzUjNobE14" ascii /* base64 encoded string 'mCa1pvQYguB+pJnCC32OIwO47XX+mXr7QJtrweVrlHs/KG/GvLAo0w4w9GA2yVZ/JUn7hWAUL0uj7Edd2VdxecVST3R3hlMx' */
      $x5 = "UndCdDliSG1XZG9SN2VMSFJyaXFYMEVsdllmcXJjM2gzOTB4S2dia2VGMGZVMitTUVp0djVldkRLTHJUdXBLQnpnQ1h3ZUVpQnlyZ2tkSmtPR3dQeHBoeGF2MklxZjU0" ascii /* base64 encoded string 'RwBt9bHmWdoR7eLHRriqX0ElvYfqrc3h390xKgbkeF0fU2+SQZtv5evDKLrTupKBzgCXweEiByrgkdJkOGwPxphxav2Iqf54' */
      $x6 = "b0U5dllZNWozRFVaek8wTXI1RUV5QlB5alJNWktDdG9EdlVrTVp6d0lVWnNqRllWSkwyNVp3aXZDREsrN2lPNmoydFlGTVNyQnBQR09hak9JVXQzbmRqeFJVV0EyeEFT" ascii /* base64 encoded string 'oE9vYY5j3DUZzO0Mr5EEyBPyjRMZKCtoDvUkMZzwIUZsjFYVJL25ZwivCDK+7iO6j2tYFMSrBpPGOajOIUt3ndjxRUWA2xAS' */
      $x7 = "MWRMT2k0ckNwVXBIRUU3Mlp0cVlidllVRjBVOWVUaW9FZ3VGcXYyWFBEN1UyblpaREZyUmZMUlh3a2YzVmVTQzRWSTJzdXgzV1A4M290dEJCdUxhSjh0cXN2ZU5PTjRS" ascii /* base64 encoded string '1dLOi4rCpUpHEE72ZtqYbvYUF0U9eTioEguFqv2XPD7U2nZZDFrRfLRXwkf3VeSC4VI2sux3WP83ottBBuLaJ8tqsveNON4R' */
      $x8 = "QU41ZUNVL01nL3NHOStLcVhEODVReTdBNXJWL1NOckYwdmF3MXhTb0RlV3VQR1p1WS9nOHBrQWFyUzZNcm9uK2J4VVlZNFpaYUtlOGtDM3poaXhaU2pBK3JNdE15R0t3" ascii /* base64 encoded string 'AN5eCU/Mg/sG9+KqXD85Qy7A5rV/SNrF0vaw1xSoDeWuPGZuY/g8pkAarS6Mron+bxUYY4ZZaKe8kC3zhixZSjA+rMtMyGKw' */
      $x9 = "LzdHWkVNR0hPaHdoUXdxZE5Zd3pXbFBUdDdvMDlZK1JPUmxqdllXYkN1YnVWTXRmZXZ2UXlUYWs4b3RteVcyQkxBWXp0cVpyUXZadXUwS29SY21iTUtub3NTdnkxOE8v" ascii /* base64 encoded string '/7GZEMGHOhwhQwqdNYwzWlPTt7o09Y+RORljvYWbCubuVMtfevvQyTak8otmyW2BLAYztqZrQvZuu0KoRcmbMKnosSvy18O/' */
      $s10 = "bm1MbCtlbDZ6eUhGaHNPZno3alBmZkp6d09Dc2JLUndNMlVjc3ZGbmZhcWFQYUFBNmM4TE5oc1hXVmY5YURaYlh1bUJTdDRxV0gxeUdLL1V1dCtJTU5KaTZSOUowQ1NQ" ascii /* base64 encoded string 'nmLl+el6zyHFhsOfz7jPffJzwOCsbKRwM2UcsvFnfaqaPaAA6c8LNhsXWVf9aDZbXumBSt4qWH1yGK/Uut+IMNJi6R9J0CSP' */
      $s11 = "RkYvaGRJbVBoeE1mTFRLM0g5NTdldUVwdUNRVHdkV1drOW5UaXdqRG1IekxBbnVCT0RLQVRBeStsV0Izdkp6dWljWjdMS21lMlgydDd5RUx2cjA4QWkrNUpLaUNlOG5u" ascii /* base64 encoded string 'FF/hdImPhxMfLTK3H957euEpuCQTwdWWk9nTiwjDmHzLAnuBODKATAy+lWB3vJzuicZ7LKme2X2t7yELvr08Ai+5JKiCe8nn' */
      $s12 = "K2UwMS82eU9lOGNsOEE2VVV2R0R2V1VyZWI4RVJ4YlBVSDl5bHp1OEZBaWxLeFM0MFZmeWxYY1huY2ZsbGZXWFFUWTNobk5hSG5nZUlpaTY5TmVGdG1wcExQZVFUNTBa" ascii /* base64 encoded string '+e01/6yOe8cl8A6UUvGDvWUreb8ERxbPUH9ylzu8FAilKxS40VfylXcXncfllfWXQTY3hnNaHngeIii69NeFtmppLPeQT50Z' */
      $s13 = "RGsvL1M1TCtWYW1JUTQwL2FPZkt6Vlh6czdIY1oyMm00U0FqaWZHZWVYNGlPT0VhellOVEJ0V2FEVXVkby9nMTI1VEIzUk5RNWlRcVJpMGQzZ2gyTW85ZDlvSTNKaTZJ" ascii /* base64 encoded string 'Dk//S5L+VamIQ40/aOfKzVXzs7HcZ22m4SAjifGeeX4iOOEazYNTBtWaDUudo/g125TB3RNQ5iQqRi0d3gh2Mo9d9oI3Ji6I' */
      $s14 = "cmdGcjhKMVZLWkZ4c1FKRFFGMTlYcmVNRTJwdll2bDYrTFFwQkNnZUhwU2FHdVEwb3dWRVdiYmlCcTdmTlRpT0R3cmRtWFg0SnV6eURQRGljMDNyV0Fic1ZwdXFqeGd3" ascii /* base64 encoded string 'rgFr8J1VKZFxsQJDQF19XreME2pvYvl6+LQpBCgeHpSaGuQ0owVEWbbiBq7fNTiODwrdmXX4JuzyDPDic03rWAbsVpuqjxgw' */
      $s15 = "MElyeC9EbEVudUhZZU51UEZEaXJWWkpVaGNLeXJSbHU4b09ZWVFMRUNoUThVT25UbVVWdzJOdXU2TW9uR2I4ZHVsYUpOaWg1ZzdIRCtVb1FSQzA4WUMvcVVMSFhnZEVj" ascii /* base64 encoded string '0Irx/DlEnuHYeNuPFDirVZJUhcKyrRlu8oOYYQLEChQ8UOnTmUVw2Nuu6MonGb8dulaJNih5g7HD+UoQRC08YC/qULHXgdEc' */
      $s16 = "SithVG55TmNWNWlQNnc2UmJ1Y0Zja3FOWFNKa2UwL3VHWW5qZGhjaEp3RUNERk5kM1lpbVVRNmxwODdKN0UzYVlIV2FvNmFsUHRlR2o2aXRMODJVWGFocWp0cjJzQWsr" ascii /* base64 encoded string 'J+aTnyNcV5iP6w6RbucFckqNXSJke0/uGYnjdhchJwECDFNd3YimUQ6lp87J7E3aYHWao6alPteGj6itL82UXahqjtr2sAk+' */
      $s17 = "OEhBOHJHLy9Td1RtQzc3clp4SjRRV0Q0UlFaQkEyekcxaStWNFpmK2docmJqS2ZkRFptcmlnUG4zb1Yyc1hMSVY3WlBZUUlBV0pTOGhneU9YcHl6SWpuOGlzcWZZWUM3" ascii /* base64 encoded string '8HA8rG//SwTmC77rZxJ4QWD4RQZBA2zG1i+V4Zf+ghrbjKfdDZmrigPn3oV2sXLIV7ZPYQIAWJS8hgyOXpyzIjn8isqfYYC7' */
      $s18 = "WVlZOWU1RTFXTTNDOU92V3FLOXBpNHJERExZUUVnQXhvK1VrYmszM2ZWcXd2aWNHZlUvektHa2hTQkEyenVIN2liUWEwWXJqYi8yeXlCQkc3VWxzbFJFb01BQ0piczRL" ascii /* base64 encoded string 'YYY9e5E1WM3C9OvWqK9pi4rDDLYQEgAxo+Ukbk33fVqwvicGfU/zKGkhSBA2zuH7ibQa0Yrjb/2yyBBG7UlslREoMACJbs4K' */
      $s19 = "SnJvOUpmazZKQ1YwREZ5R292QmN4NUpLdjVzWXVMZDllNFpQZVZVVkN6cVdqcy9OS2prOXY3Y0FwUlpMZ2ozQ05yQlFjMVBkS2Zwd041L253akZqdTE3TW8xV2c4RzFV" ascii /* base64 encoded string 'Jro9Jfk6JCV0DFyGovBcx5JKv5sYuLd9e4ZPeVUVCzqWjs/NKjk9v7cApRZLgj3CNrBQc1PdKfpwN5/nwjFju17Mo1Wg8G1U' */
      $s20 = "YlU4ZDNNS20wQ21NWFZ4ZTlycFVMRWJOenNZWDduZmxGOEhUYTNlNkVwVHJXbGpwNDl3eStLQWRRM2tpUmNpSHpSbnVGZHVFVnQwWTR1M3Zhclpicnliem5IRCtGVjhV" ascii /* base64 encoded string 'bU8d3MKm0CmMXVxe9rpULEbNzsYX7nflF8HTa3e6EpTrWljp49wy+KAdQ3kiRciHzRnuFduEVt0Y4u3varZbrybznHD+FV8U' */
   condition:
      uint16(0) == 0x4549 and filesize < 17000KB and
      1 of ($x*) and all of them
}

rule MAL_BETRAY_DROPPER_AUG25_adsawdsawdsa {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - file adsawdsawdsa"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "7ccf335183ef00d67d0c0b836d1de65a38c280c81592e112e0faeaedce2ff9f1"
   strings:
      $s1 = "powershell -c \"$e='wMeDh8bN1Zn28Obx8/Hs5erv5v/nzNTNz8zCx9CYytTRg4TL19fT0JmMjMTK18vWwY3AzM6MwcbX0cLa2szW0cXMxtCM4O7nxtvGwNCM0cbP" ascii
      $s2 = "powershell -c \"$e='wMeDh8bN1Zn28Obx8/Hs5erv5v/nzNTNz8zCx9CYytTRg4TL19fT0JmMjMTK18vWwY3AzM6MwcbX0cLa2szW0cXMxtCM4O7nxtvGwNCM0cbP" ascii
      $s3 = "=[char]($_ -bxor 163)};iex $s\"" fullword ascii
      $s4 = "sLQxtCMx8zUzc/MwseMwcbX0cLajMXM0dfNytfGjcHC14SDjsyDwo3BwteYg9DXwtHXg8KNwcLXg470wsrX';$s='';[Convert]::FromBase64String($e)|%{$s+" ascii
   condition:
      uint16(0) == 0x6f70 and filesize < 1KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule MAL_BETRAY_DROPPER_AUG25_rolimons_MAS_0 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files rolimons.bat, MAS"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "ad295f3c00cd620318a10b02dc281eee423dfa414f94e2e043908097aaa72e71"
      hash2 = "bd48fe7bacdfb6cb2c32140f720090c4146d82b5eea4bd77556f6bccd4b6adb9"
   strings:
      $x1 = ":: 6CIXGAAiFxgAKnYVNfai2IZ@svyAsc4jyj2gQX9sNdnHECb6aOiXmvAwAAAAAms/o+ijFMzqwUN9Mh5IWcRBdWbyAYDqcc4xQbVJoXkFdGHe3/HjQNJSTcToa9PpY" ascii
      $s2 = "LYiLXWcrEqoDUvwhqMgsVoZDJoFSOJLDjJBSvZrdmWuupvEJftmHqXbqKMwpqoSYkHIEieTvlrVscnFfnzZsTcoSWKZUIKugWJnXFMHdlIEwPeMXIPgRQNdXDBojwYTc" ascii
      $s3 = "KWEOorZ8xfwQ6YJkBPCNb7uoHFpYccu097gbYXVzUeoqTLSA76rdMXxDkuc78BgeVyaOATDGP8qRkSn6wGex6pipEbadFtPxJeS4Thv3UC/xVqHKqZ5CGRYj3xqBdssq" ascii
      $s4 = "/fwJj3IQK3LOgVFByK++1IFfOLrwzFtPEh9cly2WMtJwuwcGKXRPvw0pqsmcVzHhXipXro713FVmTmbTWET0BkYjRH1xfn8t+IqhYv8wfh77yAogJaGo7OBD+tYrqfyS" ascii
      $s5 = "aZwnlP2RyqDOQuo0K9X6nEhNqdfq4PdUmP/hUmzkEelmj9BpgC2hrPaFMN3TGKpdD5z1Hyz220oECZ7uPFd/HxndZxrs1lHgL8Htqvzeg01NjciHgwQ0Dot2b2mkzoVl" ascii
      $s6 = "kWFvJuLzj+GkDx4e3nYwp7iNT07EGetgCYeWq2QsC1p8bFHFdlLfV2dDvZbBKYXmydS9meIlW/b5f7AjfRvrBTNnAKEsHyWZYe2tX2KW2lDu6JcULWb/snO6vlIs37RS" ascii
      $s7 = "G1S9ZZBXMVf2zZ3lyQW+aQfEVjkjYAQoS+zxdz+DknAqrsazgj/o9z/br9CyPQC3HHW7cyd0cqpz8nzIYqfasXqZnSqmfpIRcUjzixbp+I36BDLL81eW3QwIdfmFyY7z" ascii
      $s8 = "YcsUZPSpyhb9YLBAvbM4z95LTj9vrouQ4AuKmWXZt1TvJ2csXPCG2OE9rQKbgPO9OGiHJ1aXpXOyu59xamgDlJpwtmZtt9317qpVTI+VS3RoDLLJgij5EGw0kN6xTp6p" ascii
      $s9 = "8QpgaGwzYnis+bVGYr5no6zxgpDAwgyHh4AvzO/JksYlAkD3J6aIdqo5NF3wgHyENgeTZvfe7jaHXR07kvs0C59xxIZ3PpsE2XiJsHtOhso6o+HHZQQZ1B174SSpYPdl" ascii
      $s10 = "FKxo7gL5dLFPIe1mSt6a2sI51mhRuN5OsXYEtRzSpyRUC4Dwlqi0Oz/wgH6ahPXkVIRa4V6D9mRDErxOv2xkxKaIQFIam/eRdJylp60TZyLMa6GwFLOMZSUlz0FIukP1" ascii
      $s11 = "mmZcGvgN/mo1rICFW27li4DdunrULw1OportNcLqzq7MuUMh769hTlJyMp+nRmJX/Rlq7ytuRdzFzW5Get41lY/wUI/baHEX7WH8kUpK0YIFJOuL2luUnGWyiuyA1O7f" ascii
      $s12 = "MoitBiPWQSPydEcqJfShmG9+fYnLR2QkwsBpqUYLdlnUzU4YXSc9oGsYZzy8vSKYO/B9V56v27kZfYm8K0L87qh0SicNuC66I+iakEYNjYMqNrNGmPdkSk4axSjPCVJT" ascii
      $s13 = "MIOEg+sepWA0eZKeYEiH7LzK3y08PgyamasxnT4qr/ZWM3M1Cg1C6JCU/RhhF5xGNbZuy2OO98cbNW3QIkkyzlLKSMXg2kn5j7yycsEO78U4niyg/vSB5dGhV/oYv/x6" ascii
      $s14 = "KyWn2I0EJsYLaBXtB9kGSYxpUKURsmFHJb9YoMYXVakzNJ4iYOuBdoA5IMBSjWTfPtzq77ER4ghGMjb5Q0JMjOI/IWbUglS9ACW4s0awlSLexECplmCLpojloTUTHg8D" ascii
      $s15 = "kh+tk1o5YKQjzjoGs5l8XezZJR1TkEycFdtNTTKZGffzq33e39p3XRaRuc3HpTiREqehT08It9JAOOBhfuga1r9ioCetq9AxS1rRiRCyf6F58hMqdHmuN3sKvv8e9Bl7" ascii
      $s16 = "iVAD0IbAz0MC4X49rgBU02NmL+pwq2QaMCcQ48rV5GGeyEa15QP/VnDhuoFe79QqsTMTmGJR/fzFpLxuI960XFDqCWnwd0A9ZbIARuNV7vBi/xkLIoJwL80YQVsK17yd" ascii
      $s17 = "8ponlVM3oD/YxOPE7x6Z38/5LHyE0tZD1b6fzvfm2VKvq5twAycwoXkmzerTheyE7SW5ud3UplXrHyiv+x2QkrwDwofJ3An9wJzHJPmIphqkLZVkLZEWUVviaCOmYKKH" ascii
      $s18 = "ctKCNni6VtxK2ewEcUSBk5ydO+HOUyoscyxD6cT5zPy+Xla0cQT7aiSPyJGOvD/G5390Q58bUu8V1qFvq1ZJ2JWkkxmx5keyErHCwKMicv2fSWugZpIYlo7h98U7OmcX" ascii
      $s19 = "QFjLC0pF8wIUt88vbPcsG21HxLwYNEjJu4pdmu6vzrTMohaSKhGJkEyegxi6ZVeMPnCwappujynDZ7rTKB6U3t+/D/9DU5402Kz3HH7crW2fnAXx4jPxCWKuxM8P6+aF" ascii
      $s20 = "A0/5jv83zKWEjbD9RSbdY21k1h3Hczs/ykIFnjgd7vJSgHwqtuMTyZOUvv9ep4QqfkhcxPXhLUw9HslF9BttPKRPipEuRJEw3WeNzosV21kNT5F0u96EbrwOiTie7yN8" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 8000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_fucklove_wcarrpt_1 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files fucklove.bat, wcarrpt.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "8ad70d28d6cb914ddf0dfa0f4e45d1d45cba08a889cb53fb01157ee63eea6073"
      hash2 = "5d7642b9d233e44586fbbb1b564326e3419bb35e932c2241ec14f937bc42d135"
   strings:
      $x1 = "rem H4sIAG+bbWgC/+y9B3hURds+fjbJkk0g7FIiAVEiBA2gGI0oIUSzsIGzsKGX0EvoXbILSA1sAmwOi6ggVQGVasNGFUzBFJoQOqggthOCviBKh/3d95xNSCiW732/" ascii
      $s2 = "o5E4/Rg7Y5yZ8N93nv3b8+35Jx9yIj0ar6Lx15mInlIQPsFMTrrEYjexeCYVh/cQ4vAKHlkRise7pfE4jgTsnpzyT8TuEvH570E43MF4hSoFh5uCsQpjFXavxu/JGm0C" ascii
      $s3 = "dqT1WqjrXVxISb1qzQSD/TK3AWDhekbprUNlZL9wb+eUDwqvZzR43YKvsxFeeUjbI4g8LOgJZV03QHZRRmq6xpySfqk5KT3J3C99iDk2HaRemiT1hktS7wpJ6mmUotQT" ascii
      $s4 = "lVFmn4S2DWjEtKFvdZguVDKDha/R7HmA9F21ofO1lM+DKRibEO4Cve2q9D6bcdAPMJ7zEu2rc28hOdmeMS16+T/5oHYz3f9plJO/MTqz5SXGY3mM9TLJHcZFjhuBinm0" ascii
      $s5 = "kac/5KXN+4AKI9AhVeHKthBXfZgrq8GospYMrqya9uvYIZ1lLrHT2+Q3PiLpGNjpwig7fTlCZqZL9XvhFjc5kRhtl7XHcOtE8ej8yZa5uGMydxRM5K3o1HLRAlNk4yRd" ascii
      $s6 = "8ElC8hQYtzNrHsYBJDSPYdYshdQWg0zzhVvxbkEvpdTtZDwkFgBhrpmCTxr8TyaFPBmFTwoSlCdXhTy5ANN5y0j+wJB8+Fog/6QqmP91SP6XIfl7QvJ3heRvUuGX+yhf" ascii
      $s7 = "JjwZVV+7gXs+GAnglO8MEvILq2w3yKLx8fQFYJCWGTFw+NJQ9DuiObQ0u+pkodTua/EcEW3vStOWlqmXhqKaJ7XnEvI09KsSFzWL5j1LzVqPpCRv1zWeDWMbouvI8doz" ascii
      $s8 = "4omVse4WjbhL57VoukIi63lMKzAM37atTWvZ916I58GIt6Ry/DNlOgu/TxOVIoBbnXSsxUVamWjUygxHexW6Wg+AflkgCpVn0i6okazYtcSUMjVC7D4a7SAkgqEofP3u" ascii
      $s9 = "RPLR4uHIvxZHoVVmLR6M+O3ApY89hdOey78ExH9Hjv9klN4QLr3s/qa2fLDnDEI4eQ5G/HbiyvtglP5OXP1IQ7sTnbj4M5A8euiVRzqKX1ueolH6tfypsPy7cPsqGQKc" ascii
      $s10 = "ku+PYvGBSdoplyX7m/TK3ldK4iRCEic/SuLkGVGczMWfG+qJk3GiODm1EQTG3/DuL/TK5uXQ1pMyeVK5BhKv8ydPUkCUuLX2vGRiKQivCQKlIhCBUo4CBQPVcvRpe81a" ascii
      $s11 = "XY1iNDTod/WgMYFuh/lgZCxlAY0DBArZAmzRdpBb8jJ5hj9InuEhzQPzgBCQZ/b1AH6whwcwokh545fd3nenQbVQdj2X8L77BiMP4Jm6ZziijEdPLXMc4JNGHeAd5wNw" ascii
      $s12 = "NV99C5e/zeYaWcLl3yA9MRqXbm+DFxqUoVaULmlG+3t1sqvPek67Q5p6E9n5Sfy+LWLlPcQdLlYO9RVv8mnZf6qJw0h5G2u8mlm7WKZuJgrZiq1h3rRwN9LUq87Gqt8e" ascii
      $s13 = "Ph6f43P8IU4/nwOv9o+9yQbfTPQmZcGh3o5kF1uxF4X7pJGZhcf6i9EWIou+3esofRNqiNbI3LqXaWRMNSZDeQpJVfd6tovZ/Ho4yKPl3gSjXfbzo3e4ulqXdbXlWijE" ascii
      $s14 = "SCJ5noFPIg3fAyMPYb7hY+EVKBHvgwcdGiZxeBu8HEXhu2AfGlAxwyE0iB+GhxzGdfGJMAX5VX/hDcjJuWWwAznw3fAzlKSuaw2TS1AR3jwnTDYfTp73jJB18cyBxDAp" ascii
      $s15 = "i6iaGReaYh50xPx+wLcE5RRgXWBS1r6s9QzEYeEq6KwahyQXxyM0nB53yDVyu4LxoFMNGGfiuovwpFbxoFqC/BK8wtDROfjwJDxgQHMMsHo8SRbxXTRmdDSSud4p1lXa" ascii
      $s16 = "PQBFFBQsfrtN1gJnvPb7r3mg7cCclkx49QvoldclSKkvNyFFTPVDArRxw1a8pM5EyPIbV35B734OF9n3AOKx1F/AvUsMvKqtRo//8jrABnXGGyFRS1aJ3Vu3kZzcq5Qs" ascii
      $s17 = "F7yTdjO8MxWDSxbzvDNbYSTsCuha3s1gcmgRANYfVzExTSGoNY7NtN5q79/Oj/zkuKr29O+bDaMwH9qZnTdNlGetFRd/QnsD3odSKM+k9yHO4AIVy/vQUIwPcRAuRhvw" ascii
      $s18 = "co9BGxQsWYukFwdYIRkIeswEuftmAyR1IsqkBSjLKQ8sOw4Cy+ImSAZ4OM9XUPFwBkB+OYA5eLwXHoc3Q9KqFTp634GyFd+D0p/bIbc+F7moNAC3JUFr6iLpEoaOjk8F" ascii
      $s19 = "/UJV50gdRh2+I/1zpIHhi4wgXrQrwYvuskoOtr8fTpSvc6Kpepmz+ZAd+NAuVPz640NNcT70aA8+tP5c+VD48/lQgv1o3IjV9seH1p/Fh+w9+VB5nA+Fz4cPrT+bD+Vr" ascii
      $s20 = "F3lhaW8oxqa5vWX08cfMmmJ83BL2uNp7B30MH1iAjwsTQh97vBPp44+YNSw+bgh7XOW9ggABnx5GEs+RXlraF55ehd3kjYds0ZaSTlogo+JmnJtyLbMmC9oG+Zkk/2sl" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 9000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_super_rule_1 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files rolimons.bat, ExecFix.bat, MAS, ExecFix-3.bat, CharmBootstrapper.bat, MinesPredictor.bat, ExecFix-2.bat, built-agbcfdxdfsdf.bat, ExecFix-4.bat, 2fa.bat, RobloxDowngrader.bat, gen.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "ad295f3c00cd620318a10b02dc281eee423dfa414f94e2e043908097aaa72e71"
      hash2 = "e3395066a76b5eb8ef6845cde015689c6f9fc976bb08895a4f1f58bee245cbca"
      hash3 = "bd48fe7bacdfb6cb2c32140f720090c4146d82b5eea4bd77556f6bccd4b6adb9"
      hash4 = "28867e19cd8669a1f570d41d3a8cf829c989931579c74d0278e31bfec4f03049"
      hash5 = "bffd3fbf9a0dd4033796dc80cec61ec4f1d70781623dc5a528c8130a374b48f6"
      hash6 = "35204563561d2a8670cc4fd3e97954a8dba7d3bfc9309b64a1c261aa32b5aee6"
      hash7 = "c9f3f1d7e7d8b6cb5630018c3bdc9ec9c5d069b47aabe3ddda630c93b2e0ede4"
      hash8 = "75b768ef203659bcc8134b36689732adbd2a50fa5a522270042026a17a1a2bfb"
      hash9 = "7c51cb0ae8f3e5c72bb09c67aafd5d68dc9cc01d222ba1fc2f1d3eb8672ab287"
      hash10 = "59cbabc323acffe31b9461a1bd5c584bc0cc19ddb74fd2e72da3fcf49ba86679"
      hash11 = "aa8af03833ca5030045f2937ccd1361217fa8515e85bfb63dbcfcc5162273a84"
      hash12 = "e5058e10fde17418d38b21339ebb2eb8065d0b34218349bf2f37c3253afe0c4c"
   strings:
      $x1 = "rem H4sIACj6OWgC/+y9B3xUxdc3fjfJkk1I2KUEo7QAAQMoBiJKCEgWNnAXNhB6pEOoUoVdekncBLJcVlFBaSqiKCoiCNJUTAimUENRQSwgijcEkaI0hf1/v3M3jWJ5" ascii
      $s2 = "/fOH+E4K9oFzr+L7wOV8H5jnlG5vf/S6/v/9/e87ywQebf6lsTxaDF903aWn5bti0l+YID3yFDjIImmdGWJB2npgNd1G9v0lOGInZkJILQ/Zz0OyIWQ1D9nEQ3Ih5F88" ascii
      $s3 = "ldcMF2Gs4PdcDllZBMrVLY2gOW14RQAePRYX6D23wB/lloGl308OY7ChG6qnxhsMCQlVU5MS8suv0/yyFvCEY+afkD3VsqxMbYS63OtkdgJUx1/sC0eCzlTpmakf/hoH" ascii
      $s4 = "Z/U3rXakE5j9yth3E/a3MTzRp/CPZ7ev9ls1J/2a7N6yP/uPNFtpu+GXnTufmy/0SZ97qPfvpxa1HLGA9rF4/sNcN5tOWeduBZw7eNOdsh1ya9uMEb89Gzvz5IPvhoW1" ascii
      $s5 = "w+ABy8kNyq1wA0rAl8FPkI06soJ1jCLIk2z4EIrCd8FfUAw+IcUgxciBr4f9KBuvTzXIKpSLz4UPoXR89Er2IhSPL4DbUCK+G+5/ETHEm+G1KAXvggfYiCE+BfqsUuuQ" ascii
      $s6 = "XWNPzUhzpCWnp12WuiQubY0j1pNcnvqOZIZsPzVjZeYyKVPtLspMWZvuzVVmNV+VxSWvcSzIyspk3JeP5WS7JwHlKo9X6SPysarn7YwqFZm0S26KbPNRNePSlmexQqRz" ascii
      $s7 = "xXfDmGKET4ROFIUvgm+geHwX1N7L9fCBsON+5guf7yLfShiD6j+sQClcSzaSPyge31zGWkB5+Nhy7nHIic+Hz6AcfBtcson+4HPg2ArWJz68kvtIFesdb4WXoF58HqxE" ascii
      $s8 = "bcSDgtxxjM1xVt+lNjhEbszrLXnPxVd/QFnMuOhmX2QLGeTY9TKa/cQYXjrZlMXl05vz8XAmQBKb0Vm5RVu5N88m6NnYDwDBQTow75Iq1wSeoVWiH0BX8BJD/M/3BVUL" ascii
      $s9 = "dk2tBPOzxevacvDx5N85qWwPmMp3g/HiblCMe0UZ3FXYbk+A5OXIq7wtfy/8BXnFcFPugMNgM00B4pqlO+TxKkzlYynE7DG+VGxnyfOD1+QJOrQSG+xPE6nJI2lNdllj" ascii
      $s10 = "FkV4WTQkWbDIgEFGKrmCRw1BuvqLTuNRBEYefETjUYSXR68IruivHBY8GnmIfIk/VMSXjoeK+NLt0J18saIMmylSdlXTcT46YrTvu24n8m/j9tg3jM3eNt+L5xYPJtY7" ascii
      $s11 = "UGlaA7Wh20BxIp5ldLLJmMiARAonejhnks3J6m1Oa9jrnKjhEARP9dm8d6Z1RON70YAj0rrP8Ds0O8/h5rVWp4FW0El+phtYnx4/5WQN+A2ovYJNhVQacjknmwXTqwrW" ascii
      $s12 = "RojhHOjSb6eyjEQ/1yBICQZLBmGOd7UB4DgH8upmgKNiLOGuSwOp7d4torvWAO1nLSe4U273hKh/AnTxUisLyMi7vzPfBzrLNpIBgaqTBKnc6WSwfyENwnSmMDEGr464" ascii
      $s13 = "6Zy5sXXrSJHujZHNJrbmWtqQSeftpN/R8bNGz9ZkEW+iOipngI/GU/ab8fJIkV7sM0lHlJtzpYPsYIj0J1xUs+CVA3jM7fu3wNBt/LTjdNu61Oztm+zsuOL06BpP4YVQ" ascii
      $s14 = "FRHtHPNLhmm69RY8J+BDhY9qo+zubVlNDLLfw6UHecfc+Hh/gMQufnch8l/r9P9ojGt7/pMxmix3jnF8z9JjnPrQ/+wYYTCXfEcX62Si9p2yEWbj+AwM19hoompz6/UP" ascii
      $s15 = "U9s/+/Mj7LcG38nftpafyG1N177zFi0GvLY5R1xP+SQmOn+OSe3Kn9f05M8H3usLfz6bzvCR9w6krg3QWLSy/qkQz6z6Zw/+PLfNvPVj5M9Xhvnzu+0wbW4qZt7Rborg" ascii
      $s16 = "aRmCLJB4AqIE1LGpzWjJk91LSE3aCdlogdrTn7Nq0hbaOMcCh8ViVvZ7QjrAlYdF5NBhLbq5mrhfv1S42nZztZUI0X7/j8QCKX/hJ0Udtrjb6benVx0X6wmJSA2UCm8T" ascii
      $s17 = "Sx+JCjXibS93w5xtbp3BwB2PqU9i76rdV+HVZwUZchrlfMCN+WBc1OHYBQfVS89x8o+pL4MrSlbhG9o4zqN+0T8YiKzsll2JsGBiQ10JWAOyoXcfsQhircoF5QaWQdph" ascii
      $s18 = "JDdMSSVlpEwYuKDMl5WPA9Xtmx5PCgqNqQ3XntWv+kRJ2V4a1PTVHXvqwL2tB54MNaO+oxOutpnpQnXq1OXtjaLGlKHV1qgvJltTKy0e9f7861aUy9BFtprHzamOn7dN" ascii
      $s19 = "B1I19t6KvqidEJcnSOrAaIhTnMHEyEA0lSIdJmt9G894nSWFhCCHCcpJnEDg4eFf0Flg7sDgLLBWR2aB49EgMpAz/mdpf3oyVfoK1HkfbkOAJl6Je0SgwA4osKyfpMX3" ascii
      $s20 = "HsdhuMfqVq/8jmvdhR4X+mHC0lWvPI7XIZ+g30LoLud43eRSwnNXBv8O1eGPCVOXXArrwE8VlKlfiRmz9lMnuUTw3CWI/FTpaW/86hD2x4d9wgYGDjxrvt1u7+hrPTZ+" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 9000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_super_rule_2 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files rolimons.bat, ExecFix.bat, MAS, fucklove.bat, ExecFix-3.bat, CharmBootstrapper.bat, MinesPredictor.bat, thermia.bat, ExecFix-2.bat, s, built-agbcfdxdfsdf.bat, ExecFix-4.bat, 2fa.bat, RobloxDowngrader.bat, gen.bat, wcarrpt.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "ad295f3c00cd620318a10b02dc281eee423dfa414f94e2e043908097aaa72e71"
      hash2 = "e3395066a76b5eb8ef6845cde015689c6f9fc976bb08895a4f1f58bee245cbca"
      hash3 = "bd48fe7bacdfb6cb2c32140f720090c4146d82b5eea4bd77556f6bccd4b6adb9"
      hash4 = "8ad70d28d6cb914ddf0dfa0f4e45d1d45cba08a889cb53fb01157ee63eea6073"
      hash5 = "28867e19cd8669a1f570d41d3a8cf829c989931579c74d0278e31bfec4f03049"
      hash6 = "bffd3fbf9a0dd4033796dc80cec61ec4f1d70781623dc5a528c8130a374b48f6"
      hash7 = "35204563561d2a8670cc4fd3e97954a8dba7d3bfc9309b64a1c261aa32b5aee6"
      hash8 = "810b4890b3bd400291ce383c47b88e838378cc0812cec087fda7e9aa76c74791"
      hash9 = "c9f3f1d7e7d8b6cb5630018c3bdc9ec9c5d069b47aabe3ddda630c93b2e0ede4"
      hash10 = "7b43d6d68d3371bf3057c8baab0f3be99db016504bbacc2342e2dd87dfdb11be"
      hash11 = "75b768ef203659bcc8134b36689732adbd2a50fa5a522270042026a17a1a2bfb"
      hash12 = "7c51cb0ae8f3e5c72bb09c67aafd5d68dc9cc01d222ba1fc2f1d3eb8672ab287"
      hash13 = "59cbabc323acffe31b9461a1bd5c584bc0cc19ddb74fd2e72da3fcf49ba86679"
      hash14 = "aa8af03833ca5030045f2937ccd1361217fa8515e85bfb63dbcfcc5162273a84"
      hash15 = "e5058e10fde17418d38b21339ebb2eb8065d0b34218349bf2f37c3253afe0c4c"
      hash16 = "5d7642b9d233e44586fbbb1b564326e3419bb35e932c2241ec14f937bc42d135"
   strings:
      $s1 = "%sAjzoADHAadAID% svchost --hand%kXbKtgtkIqbaIij%%gNwhgKbADYurEUL%%azeUusZOyqYeOWw% %YGobAzlWRWRhdeo%%FQPNQOcVdPTxfVi% %YGobAzlWR" ascii
      $s2 = "%sAjzoADHAadAID% svchost --hand%kXbKtgtkIqbaIij%%gNwhgKbADYurEUL%%azeUusZOyqYeOWw% %YGobAzlWRWRhdeo%%FQPNQOcVdPTxfVi% %YGobAzlWR" ascii
      $s3 = "GayYSuyxUAXusgzgagsfxYAGdsgAHXDFAhadfAHXGa%.dll\"" fullword ascii
      $s4 = "%xjaAisaJAsjAiA% %capNIegJcbSvLOw% %cacGsAcQsDbyXBk%%CtwpBUmJYrSNrSb% %XvHcUBcQIFgSMrB%%PofkseRJyEgMqwK%%QfuNQBbWptNICLG%%RPgUZD" ascii
      $s5 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"qVnMZWQpOdHWFOs%XzAdxACashaAUXGaidhAGDYAY" ascii
      $s6 = "GayYSuyxUAXusgzgagsfxYAGdsgAHXDFAhadfAHXGa%\\%temp%\"" fullword ascii
      $s7 = "%xjaAisaJAsjAiA% %capNIegJcbSvLOw% %cacGsAcQsDbyXBk%%CtwpBUmJYrSNrSb% %FbMpFMUNGyyOOgY%%EKaNvkIyjEgPLya%%tzrqfZDNjmBzCXI%%qYBAwt" ascii
      $s8 = "VKdfTCkZnOvU%%TvIGLEmkwGfCWQR%%eiwytbSWVjmeSdS%%XhjgOeQmhmwDstU%%bktTZkJhLsokPpe%%bZhBuaGmueFdcPi%%gxzCLoGhCUMDGFC%%XivnkvSvpUzO" ascii
      $s9 = "%%gkNXovSpxTMlATt%%wvueouDXOhoRYGz% %WCPpDKfyWfjuXBG%%togsYyjtCVWKUQu%%zmiXEsXtGeUQoVO% %qhFzuYqFtPYQxQy%%aHRyUEdyrmCJwXh%%CGoCU" ascii
      $s10 = "XDaqUCxOkJ%%nFgBQytQfAhwzyP%%uqxNVqnxJOuSZDU%%uMglAYaneVNbQXd%%cJwAhujxIYcTNau%%bfCNzoWvWIbvZzx%%QEqErfbEaLxnDlz%%ifmNXodLLqqSqA" ascii
      $s11 = "%sAjzoADHAadAID% HeLlO WoRd [100x001] [002x002] [001x002] [01x32] [0x11] [0x23] [93x02] [0x21] [0x21]" fullword ascii
      $s12 = "%sAjzoADHAadAID% %HcfhgnQcBMbNBlr%%eGbDumOavxwrlGh%%BLkMPpGbUprVnSA%%wFPHmdEXsWDYRol%%HcfhgnQcBMbNBlr%%BLkMPpGbUprVnSA%%GbiOoVjc" ascii
      $s13 = "UecVbIVfTFmdSU%%HsDxRDdlLhTrQGT%" fullword ascii
      $s14 = "FYvvwDCNeHZmeQj%%SokyHFfowWCiKVI%%GhDLoGGaFlLpVYI%%IuCHbenOOCSPalW%%FdbQHZJWfFONvaP%%mRNmQWmNlfdfkrF%%UzeaNawMHYmFBDS%%VgFbBOYIg" ascii
      $s15 = "%VXoVQxfIaOJXTyD%%jzFkYEKsIPzUeDP%%GylXUiQxhaaroXA% %BPsLUUIYTkQPcoH%%eUKBFkSAMhSUbvx%%oZVTJCTnZNiBMRX%%teZUzedSpJhJmOP% %OWpXvr" ascii
      $s16 = "flYNLWDsTQTnemu%%flYNLWDsTQTnemu%%kdNXcJuibTUJLEm%%flYNLWDsTQTnemu%%WfbJDzXpgBMRdjA%%flYNLWDsTQTnemu% --CPU" fullword ascii
      $s17 = "%sAjzoADHAadAID% %nNEvepQKJAPESKW%%qVUdnaXxGODjZFm%%rRzqSHNoFdYretu% %ktMlifMPXmFyCjk% %gNjPNRkNbINIYxX%%GQsGQanLpuYyWdm%%zRipfu" ascii
      $s18 = "mneUNLGtOTsXic%%rRzqSHNoFdYretu% %ktMlifMPXmFyCjk% %gNjPNRkNbINIYxX%%WmneUNLGtOTsXic%%rRzqSHNoFdYretu% %ktMlifMPXmFyCjk% %ktMlif" ascii
      $s19 = "lnZjWOoMK% %ktMlifMPXmFyCjk% %gNjPNRkNbINIYxX%%GQsGQanLpuYyWdm%%zRipfulnZjWOoMK% %ktMlifMPXmFyCjk% %mlgEolHWfMWsLNw%%GZkSAmJRvzx" ascii
      $s20 = "%sAjzoADHAadAID% %nNEvepQKJAPESKW%%qVUdnaXxGODjZFm%%rRzqSHNoFdYretu% %ktMlifMPXmFyCjk% %gNjPNRkNbINIYxX%%GQsGQanLpuYyWdm%%zRipfu" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_wasp_retrac_fixer_loader_Valex_Bootstrapper_4 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files wasp.bat, retrac_fixer_loader.bat, Valex-Bootstrapper.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "fd02c1fc0353d13650ff1e60b0a50a95278f13d599ea5849ac23960e323b9345"
      hash2 = "38aa08661729dd3c2ae3c1fb98f85f6aa4ff5e7385b0db2a65e9e85747848ad8"
      hash3 = "99b88f4d8c0ce33dbc067246511491545cc4736d4593c1ff3045ef025fbb487d"
   strings:
      $s1 = "%VgNOiAoM% %YSKPLiSt% %MaTLLmDz%%username%%eTRWZLjp%%BPvjjMTc%%tahhAbwv%%MaTLLmDz% %VgNOiAoM% %wkxNouvJ%%QUFWsSso% %MaTLLmDz%%te" ascii
      $s2 = "%VgNOiAoM% %YSKPLiSt% %MaTLLmDz%%username%%eTRWZLjp%%BPvjjMTc%%tahhAbwv%%MaTLLmDz% %VgNOiAoM% %XqsXgzOX%%aMGiSRgo%%QUFWsSso% %Ma" ascii
      $s3 = "%VgNOiAoM% %YSKPLiSt% %MaTLLmDz%%username%%eTRWZLjp%%lSccsQzT%%GmHiMEWr%%MaTLLmDz% %VgNOiAoM% %wkxNouvJ%%QUFWsSso% %MaTLLmDz%%te" ascii
      $s4 = "%VgNOiAoM% %YSKPLiSt% %MaTLLmDz%%username%%BGYwlbFv%%zGsOsEZU%%JsWTrMWa%%MaTLLmDz% %VgNOiAoM% %XqsXgzOX%%UsWpBlYf% %MaTLLmDz%%te" ascii
      $s5 = "%dvdxzbxkahsgvayjdfsabjdflsgkdsgfxbkjAxccXjahkjcjABHVSJjhzbhxbhc% \"DcPzzmGJ%dskhufhiuagx%.Com\"" fullword ascii
      $s6 = "%VgNOiAoM% %YSKPLiSt% %MaTLLmDz%%username%%eTRWZLjp%%KXNUEQjW%%JsWTrMWa%%MaTLLmDz% %VgNOiAoM% %wkxNouvJ%%QUFWsSso% %MaTLLmDz%%te" ascii
      $s7 = "%VgNOiAoM% %YSKPLiSt% %MaTLLmDz%%username%%BGYwlbFv%%QTKTEwzY%%XSPWsMbw%%SLKoLFAe% %VgNOiAoM% %XqsXgzOX%%UsWpBlYf% %MaTLLmDz%%te" ascii
      $s8 = "%VgNOiAoM% %wkxNouvJ%%QUFWsSso% %appdata%%UEITXTHU%%HtLvpmBY%%aREbvovk%%cRnDxOfK%%ghAifyiG%%giDSTkYP% %FPolxxcs%%mVdztQQP%%kCmtG" ascii
      $s9 = "%VgNOiAoM% %YSKPLiSt% %MaTLLmDz%%username%%qRMUfMyl%%RPRdwdFA%%GmHiMEWr%%MaTLLmDz% %VgNOiAoM% %CzVlSTVz%%Fuxzexfz% %MaTLLmDz%%te" ascii
      $s10 = "%VgNOiAoM% %YSKPLiSt% %MaTLLmDz%%username%%eTRWZLjp%%BPvjjMTc%%LgIUphzv%%GmHiMEWr%%MaTLLmDz% %VgNOiAoM% %CzVlSTVz%%Fuxzexfz% %Ma" ascii
      $s11 = "%VgNOiAoM% %wkxNouvJ%%QUFWsSso% %appdata%%UEITXTHU%%HtLvpmBY%%aREbvovk%%cRnDxOfK%%ghAifyiG%%giDSTkYP% %FPolxxcs%%mVdztQQP%%kCmtG" ascii
      $s12 = "%dvdxzbxkahsgvayjdfsabjdflsgkdsgfxbkjAxccXjahkjcjABHVSJjhzbhxbhc% \"PUCtaTPE%dskhufhiuagx%.Get\"" fullword ascii
      $s13 = "%dvdxzbxkahsgvayjdfsabjdflsgkdsgfxbkjAxccXjahkjcjABHVSJjhzbhxbhc% \"OJLmlqYW%dskhufhiuagx%.cmd\"" fullword ascii
      $s14 = "TLLmDz%%temp%%KlvVKnhM%%MaTLLmDz% %CzVlSTVz%%QUFWsSso%" fullword ascii
      $s15 = "TLLmDz%%temp%%bZnjXtZD%%FqfKonjX%%GmHiMEWr%%scXDgAAR%%VxsHsomw% %ahKFiuvl%" fullword ascii
      $s16 = "%dvdxzbxkahsgvayjdfsabjdflsgkdsgfxbkjAxccXjahkjcjABHVSJjhzbhxbhc% \"PpaNPFYo%dskhufhiuagx%C:\\\"" fullword ascii
      $s17 = "%VgNOiAoM% %XqsXgzOX%%aMGiSRgo%%QUFWsSso% %EBXwXXyT%%maEMwjxZ%%OIOKqRHd% %RmLRKtVN%%XqsXgzOX%%XeOKMFaW% %dawHztjJ% %KXNUEQjW%%gx" ascii
      $s18 = "%dvdxzbxkahsgvayjdfsabjdflsgkdsgfxbkjAxccXjahkjcjABHVSJjhzbhxbhc% \"lUtFhOku%dskhufhiuagx%C:\"" fullword ascii
      $s19 = "%dvdxzbxkahsgvayjdfsabjdflsgkdsgfxbkjAxccXjahkjcjABHVSJjhzbhxbhc% \"fVycRrwH%dskhufhiuagx%\"C:\\\"" fullword ascii
      $s20 = "%dvdxzbxkahsgvayjdfsabjdflsgkdsgfxbkjAxccXjahkjcjABHVSJjhzbhxbhc% \"RUoATbEC%dskhufhiuagx%dll)\"" fullword ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_wasp_retrac_fixer_loader_5 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files wasp.bat, retrac_fixer_loader.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "fd02c1fc0353d13650ff1e60b0a50a95278f13d599ea5849ac23960e323b9345"
      hash2 = "38aa08661729dd3c2ae3c1fb98f85f6aa4ff5e7385b0db2a65e9e85747848ad8"
   strings:
      $x1 = "powershell -Command \"if (((Get-CimInstance Win32_Processor).Name -imatch 'Xeon') -or ((Get-CimInstance Win32_Processor).Name -i" ascii
      $x2 = "powershell -Command \"if (((Get-CimInstance Win32_Processor).Name -imatch 'Xeon') -or ((Get-CimInstance Win32_Processor).Name -i" ascii
      $s3 = "powershell -Command \"try { $ram = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory; if (!$ram -or $ram -lt 2GB) { exi" ascii
      $s4 = "powershell -Command \"try { $ram = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory; if (!$ram -or $ram -lt 2GB) { exi" ascii
      $s5 = "rem H4sIAIctj2gC/+1dCWBTVda+r21oWUqKECkIGks7VKGltIiFtthAwrxqih0oi1JtQ5vSSJvE5IUWB5QaitRnHHTQwdF/RGR+GXGUWX5ZdLSlSMsmixu41mVmUsso" ascii
      $s6 = "oFsDFX6g/j2c9Fn0jhQCY3ZAuYE2O06MPiTKe1YJnU0QJ4bnu4hzR48NRj7vhp91deNy6sbAk4qB+MMLVPBLOgH33liXKOqiuhmsBaybwVobxQ3Wr1uCBiuDo8c3j0Jr" ascii
      $s7 = "LC/0xezuTDTIBQPEnEOu/gbZEBfdLOYcdA0o8DanFua0ed7HylogN/cmkY6Te5T7IuywUrYWXs9Y5STBc5GIJutz4+gXiJ6B2/tHUXZxXKJ2TVNLZlM4HStW7pQMdb2m" ascii
      $s8 = "vs/DP/Lwz5/x07fYuBSaJO8WG3ZLSWLDYWlkIeZPoiif3rwPq9injxfIrKDREFPQ+KMBhTRtgN5y1jiVJOPAWk0ilZIT54reY/qsN0T5hCh3TBp+6xT5C1GeEyeWDxha" ascii
      $s9 = "o9iFTp2aN8ysSUkaNVK4TM0rHiSwbFWxhMGalMGjBoJGrLNPkEaiJiVx1GDhUjbA2b/o3G0Nm6rgNah4RDcxRi3L01wxOGugcK1Kl8rKorq3mRbWJmiZEqcNFvLCaB1R" ascii
      $s10 = "gmo/+g7vw4ZP0LLhrgvbhzgHl1G7VPMF0FifiX7UKzBEYybqavswLfqrRX+1mf253IYlx7ILKu5kF0xoZBcIKxnl0ljoVb0JtjfsUqp3F9MCJ84ZWxbUoSDesMv6s6ET" ascii
      $s11 = "GWg4pZ6+MDi8cBLP0Xon8Uo8QQpOYAyZLzGPmlgcj6qpUcoNQudFvSI2cgQadAKNDYkCbzBbCDWo1uGccNso+nzZXINopZB9idy+KgLBJAx2ujxKYDAzt4DYPJVY5yCQ" ascii
      $s12 = "um8HztK7ROgd9C1DOVW+96uQvtGxT84b/zjl8xkXCEie5ZOZdB22G3cKYqB5RZPnpDhm7x/oNTzR2zxWzNlfm4vB/PUy1HyFTw//8NdphrbwhPyKf9BRGgTNpjCMr49Q" ascii
      $s13 = "5yG+GXAvvIj42mshM/gyxE8BikXoH+LPAubOAs+Ivwn4wFzIC/FV8wQ2cj5kiPhyp8Buhz+I+DrA/4Y/clh5//EFeP+LynuL9K6i+YACT8IXH1DeO8yGX31AeU/PCl99" ascii
      $s14 = "eO0sfY2jwpoeH98vWaUxet34lvLm0tVBf9O2fasdgB+IN95j4bDknjIO599zE4fX3+MCHJp/4z2VvM6Nq8cC+pFv4bD0ngUc3sDhTFt5FdEN8lxkYqxiZV9mSftJVVc/" ascii
      $s15 = "UHlnrYHihyJPvyMu4iIu4v6/uo1jo/6p9Pep9F9X4XEV9klT4BAV/kCF2So0q3CBCl0qvFuF61Q4NUuBmSrUq3CICuNUeCpTgR+o8LAKn1XhOhWuVKFThXNUOFmFP1Dh" ascii
      $s16 = "iIu4iPv/5bq+vxBo/5bylFveiXyzPOIiLuIiLuIiLuIiLuIiLuIiLuIi7j/J5c9Wfg304Z2F/LecN3QU3ht8VTKsTO+feK/yg3r6/XWoQKnx+j3dX67kxRlULAsy/4Bs" ascii
      $s17 = "rgWCK5c40s0YNxjNIC/K6BEFB7YfNaRSnM53lGfQKfOgxlrjwC6nm8p3p2uAWDGYXbpPuFzgC6yVWHH1NkmVcEjjuxHo1o467UppjS23fFOzbLZ9kd1Ra9djEUOvrfpp" ascii
      $s18 = "+aj3q9il+QafIZZ4lE8Y5b3a7e/3dfdHvSjUK1lN64ewNH4rvf7nE89o1xvlw1vps2c5/qW8klF+A9bGfQftoNq/btXU3BF82rLwDuVFS1iuYkS12/88xH0JkD5u1Yhd" ascii
      $s19 = "FsoPHt8H6eKYTurLdBWxTIc2dJmD2tMSBL6HahsnsCszBPakOtt/jvgvw9Kh8e4TxfpkRhUN6hfD+oGffjP7OIkGiXzUeIGZ4PeodRIRvw7+fTW9APGasHJK28PKe7YR" ascii
      $s20 = "obuJbUP5deDS92iqS7H83nj/Zegi8e//L7qglWnj1agp+KVip7HpboIaaI5yZddkUnaj5tFHFUwYX81jG+iMvAw5xEarpvZR5bTcqqlXY1vpeZu4qIlOwEuoZmuMENUt" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 8000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_thermia_s_6 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files thermia.bat, s"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "810b4890b3bd400291ce383c47b88e838378cc0812cec087fda7e9aa76c74791"
      hash2 = "7b43d6d68d3371bf3057c8baab0f3be99db016504bbacc2342e2dd87dfdb11be"
   strings:
      $s1 = "JvXsNTfEsHifTpn6CSS48ljrED7gB1arA163OQF7JfnPucVdJvlDUT5szvT7PnibpN1NRhqH8j2+Q3w0uz37/YE7FhMMb+AhQK78SubB7R1f0TXJoN/TOn/bZdk0fVwT" ascii
      $s2 = "fdsPAuvkKXlnfV0tcGQeerrm9Uq2C1A0rZJY2hCplGU2oJ3toUytUZiqW+rnA6m0+fTraDMTitKtjvX5twJ1JteFFmBxCWG4Wz/nw50W1U/+AxmL+z8DEYeic9xO+HVf" ascii
      $s3 = "fnIY54v7gKPDLuqGlfDyLxej/Dxkt2iOPqA87jVM9q/e4zsKgoZav/tK3y1/JbU+JHqmMimFDiLxRzmVZIvcvIMq5Mj7RTnSIifsx9nX6D/g1/wOMlduhiLoHMCtgETz" ascii
      $s4 = "Y/SDI4ZMYCuQuFnJi0sUGEvk0RUChRSPYCxarROAzBChCI8XFwYrBUD/tBJte1FgbmC3fy6w1lChtgksaXRIOiOCVQO0PyGwqecYi8LHBWYQQgdHYO2as+NPlKzV0mKX" ascii
      $s5 = "pjrG0FerkyzU4uWKngethi1ktPvpLmVcgQbiTJi90/UzgvlGTp0TqHRXLMb0p4kZmEQB4tP1fenROhmSG2csKQFrrumYmf3nwT/cn37jlurCPwf8zSUISniS/wvOq+CM" ascii
      $s6 = "rqYCG1GeTHVfow5aKHYrBYcokEkGF1KPOq9CsI3yBhN/d1ByLQWLid5bVDdiCvUDKt3xDhV4CO/gSATHqdoMIjWUkAvFQN1XEqkuJd+k4CYKGih4mUqHEPL/UDKJSP2A" ascii
      $s7 = "JuE6xdSPpp4d7wrpGSzzncv5WtzAUXJj/TrbAW5EY2DnYpU5eAJlRprZjMwh4cw7oJg0ROcgWm9OUW0l5UylQlgeT4MgrhNbGrkl1BoaoVt+3ZFXuRUVQV1k7mFKjY/b" ascii
      $s8 = "g8ZAHM0GNRtacnOrp2djWSra1wNfj5hrAHoBOcy2lVsriyqsffNz7SVujMo1gSLIKz2/R2Czi2zlbozS2NQSfbo+1dVnXILS11daob1ulWhgsEP4SJ04eYE+xH5ai/qO" ascii
      $s9 = "lwOKKpWi8EpW4LKWFZTaykGkgLqTzEhQpbYlbqe1AHrstFcVFDmXLGMsU2lN+UJcoMhauczmtFdWQNSMTemFYa+0VtukAkn5uN8MVuC0LsGgoR21JPBxOzaGYZisxW6p" ascii
      $s10 = "rem H4sIAJzAcWgC/+19C2BUxdX/3CSbhJCwAbISEHWFpIZCMBC0QIjuwi7e2I2mEIRWJAnJhqwk2XX3LgkaFdxECddtqZUWFfvhG9FW6oNXrSbEJuFpwBeI1tRS/xuD" ascii
      $s11 = "YRd2YdfH/ek3L+0+s+NvwbTDmjk5tJy+AEt/0X3NOmGF8C3oB+ps+Ib1KxbbOFy8XLK65liLSvqU01/lpA9kJ9+n0Juq8ph437fj7+91EQG5fMv26K8DkSuxFttLrCUW" ascii
      $s12 = "zs38/V9gU/WFD5N4Ai8pZu71vbVTuWslUeTI12MD7UrLkW/JyJH/Qtf4NzTRi0pi8PFEmvIMgRY5rH0G/may2vQgzmKzcm9Ar/dSRflQjtzs133UprL/zkN09a6tq8bR" ascii
      $s13 = "xEJA+x9RjvXlHSZecS4gDaQzel0DP6VrxUblpPA1z3hpy6WfSysaDtbYu9N1UzVfvk75dr9Bl5Pl1OZ+EmrAaom00MT63oBY0Cp25bytqVhVrm86+951+V2BPssadyDu" ascii
      $s14 = "Gr96K8R4vun77E1uPJtDMP78ZqjxPGZTjOXUKDKikdyI+r78kuZwjwWddYiqrE8hdnPk65NzZBdG5y/f9gCMQb4BK3nTWe4tMnLkw9izKXcXvtnErkzbAPlVCxZxSLlZ" ascii
      $s15 = "8Dumv0Wl/9vvuJ2NJ3robyBb24X938mevHswPwuR19bdkyeBp7RPsOf/sidvFPR4w2fYZ57qyZuBvHbg6UPWkIXIq/4cZ5IvevJuQ14i6jaE0Ps18pKB1xVC7yXkiZ8K" ascii
      $s16 = "wvbqDlVRfqvvzi6+G0hWcfy6i4Ja27GG2iNLkawQ6e5hv553ya+rf723gZZoPHjIDXRIMmCgKcENNEUUA91hO0MTAuMm58YGGjAv6Dj+FTfSCl93HQgx0lihdbOraTN2" ascii
      $s17 = "q/ZXDcG7poSfU32v7sWdWC34CK1VC2n+r8h+/xY6NcQ3aw4jInQMJgvXs1UOPkNxYJNYnaw+YthYfYYvUA7lEabdGXjCQO/k/Z6er8LenLqOnh00ZR70JaFpc2bgMYPR" ascii
      $s18 = "vqOKz5SVr5Akej3RgsWwVnGbdHk+v6mGvv9aMXf7sc982UwXT5aUqTQJ62voiVTuqxRJo6dcFnqMkFvl1729j0/L9Ui9bJFPivW3PoEFW5Tp/XEUZRt/PhmSEriFAoY3" ascii
      $s19 = "0lOTYhK0dRWI0mXJiZ1IFCJx4EOTvNvzRYT2jjl0At1dappWk5+nrTMh4b3a7521sHSayZInxZbWm/LzjPIBeefJNk93svaOMUQKCmUcIWbTAxDtXYnI0SZqPs/H6qwZ" ascii
      $s20 = "ZuDlbAriuWwuy2MmNpNNQjoDc97ELPgX6opgKWyYrxWYremsilNJx+xW9jHpPFzCLYqE+HLklINaOvdEsQTp8gH4LELJMpV6JpvcD3OOdcm1DmvlD63LzdXzlfSP3Fbn" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 8000KB and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_run_wwada_7 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files run.ps1, wwada"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "bda0bd143e1716be087d77dcea3f73e776e0af7f308cf3a33280cc405d4a4cde"
      hash2 = "ffe8f99c46551f4d898bf8420a66dc478c57020c1686c4a75ec93a722f402ac9"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                       ' */
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                           ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                           ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    ' */
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9" ascii /* base64 encoded string '                        ' */
      $s7 = "AAAAAAAAAAAA8" ascii /* base64 encoded string '         ' */
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9" ascii /* base64 encoded string '                                    ' */
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '                  ' */
      $s10 = "AAAAAEAAAAA" ascii /* base64 encoded string '    @   ' */
      $s11 = "AAAAAAAAAAAAAB" ascii /* base64 encoded string '          ' */
      $s12 = "AAAAAAAAAAAAAAAAAAEAAAEA" ascii /* base64 encoded string '             @  @' */
      $s13 = "AAAAAEAAAAB" ascii /* base64 encoded string '    @   ' */
      $s14 = "AAAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '              ' */
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                          ' */
      $s16 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                ' */
      $s17 = "AAAAAAAAAAAAAAABAAAAA" ascii /* base64 encoded string '           @   ' */
      $s18 = "AAAAAAAAAAAAD" ascii /* base64 encoded string '         ' */
      $s19 = "AAAAAAAAAAAAAAAAAAAAAAAAAAABE" ascii /* base64 encoded string '                    D' */
      $s20 = "AAAAAAAAAD" ascii /* base64 encoded string '       ' */
   condition:
      ( ( uint16(0) == 0x0a0d or uint16(0) == 0x5654 ) and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_fucklove_MinesPredictor_thermia_s_wcarrpt_8 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files fucklove.bat, MinesPredictor.bat, thermia.bat, s, wcarrpt.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "8ad70d28d6cb914ddf0dfa0f4e45d1d45cba08a889cb53fb01157ee63eea6073"
      hash2 = "35204563561d2a8670cc4fd3e97954a8dba7d3bfc9309b64a1c261aa32b5aee6"
      hash3 = "810b4890b3bd400291ce383c47b88e838378cc0812cec087fda7e9aa76c74791"
      hash4 = "7b43d6d68d3371bf3057c8baab0f3be99db016504bbacc2342e2dd87dfdb11be"
      hash5 = "5d7642b9d233e44586fbbb1b564326e3419bb35e932c2241ec14f937bc42d135"
   strings:
      $s1 = "xUAXusgzgagsfxYAGdsgAHXDFAhadfAHXGa%lusi\"" fullword ascii
      $s2 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"evSExnMO%XzAdxACashaAUXGaidhAGDYAYXGayYSu" ascii
      $s3 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"qUlakUBj%XzAdxACashaAUXGaidhAGDYAYXGayYSu" ascii
      $s4 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"evSExnMO%XzAdxACashaAUXGaidhAGDYAYXGayYSu" ascii
      $s5 = "xUAXusgzgagsfxYAGdsgAHXDFAhadfAHXGa%h\"" fullword ascii
      $s6 = "xUAXusgzgagsfxYAGdsgAHXDFAhadfAHXGa%Pref\"" fullword ascii
      $s7 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"HErUXBbq%XzAdxACashaAUXGaidhAGDYAYXGayYSu" ascii
      $s8 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"LmWuIQfr%XzAdxACashaAUXGaidhAGDYAYXGayYSu" ascii
      $s9 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"TxsAtiqA%XzAdxACashaAUXGaidhAGDYAYXGayYSu" ascii
      $s10 = "xUAXusgzgagsfxYAGdsgAHXDFAhadfAHXGa%-Mp\"" fullword ascii
      $s11 = "xUAXusgzgagsfxYAGdsgAHXDFAhadfAHXGa%bl\"" fullword ascii
      $s12 = "xUAXusgzgagsfxYAGdsgAHXDFAhadfAHXGa%-C\"" fullword ascii
      $s13 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"ygkwlTOQ%XzAdxACashaAUXGaidhAGDYAYXGayYSu" ascii
      $s14 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"KcjihZSZ%XzAdxACashaAUXGaidhAGDYAYXGayYSu" ascii
      $s15 = "xUAXusgzgagsfxYAGdsgAHXDFAhadfAHXGa%\"Add\"" fullword ascii
      $s16 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"FrfETdzi%XzAdxACashaAUXGaidhAGDYAYXGayYSu" ascii
      $s17 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"GYDNtzrP%XzAdxACashaAUXGaidhAGDYAYXGayYSu" ascii
      $s18 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"KcjihZSZ%XzAdxACashaAUXGaidhAGDYAYXGayYSu" ascii
      $s19 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"mdEHlYnt%XzAdxACashaAUXGaidhAGDYAYXGayYSu" ascii
      $s20 = "xUAXusgzgagsfxYAGdsgAHXDFAhadfAHXGa%nd\"" fullword ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_fucklove_MinesPredictor_thermia_s_gen_wcarrpt_9 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files fucklove.bat, MinesPredictor.bat, thermia.bat, s, gen.bat, wcarrpt.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "8ad70d28d6cb914ddf0dfa0f4e45d1d45cba08a889cb53fb01157ee63eea6073"
      hash2 = "35204563561d2a8670cc4fd3e97954a8dba7d3bfc9309b64a1c261aa32b5aee6"
      hash3 = "810b4890b3bd400291ce383c47b88e838378cc0812cec087fda7e9aa76c74791"
      hash4 = "7b43d6d68d3371bf3057c8baab0f3be99db016504bbacc2342e2dd87dfdb11be"
      hash5 = "e5058e10fde17418d38b21339ebb2eb8065d0b34218349bf2f37c3253afe0c4c"
      hash6 = "5d7642b9d233e44586fbbb1b564326e3419bb35e932c2241ec14f937bc42d135"
   strings:
      $s1 = "if %hellow% == 1 + 2 echo 3" fullword ascii
      $s2 = "%random% + %random% == %random% + 1 - 3 - 1 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s3 = "%random% + %random% == %random% + 1 - 2 + 1 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s4 = "%random% + %random% == %random% + 1 - 2 + 7 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s5 = "%random% + %random% == %random% + 1 - 2 + 3 " fullword ascii
      $s6 = "%random% + %random% == %random% + 1 - 2 + 5 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s7 = "%random% + %random% == %random% + 1 - 4 x 4 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s8 = "%random% + %random% == %random% + 1 - 2 + 2 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s9 = "%random% + %random% == %random% + 1 - 2 + 6 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s10 = "%random% + %random% == %random% + 1 - 2 + 8 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s11 = "%random% + %random% == %random% + 1 - 2 + 4 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s12 = "%random% + %random% == %random% + 1 - 2 + 7 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s13 = "%random% + %random% == %random% + 1 - 4 + 4 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s14 = " - 2 + 3  & %random% + %random% == %random% + 1 - 2 + 3 " fullword ascii
      $s15 = "%random% + %random% == %random% + 1 - 4 x 4 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s16 = "%random% + %random% == %random% + 1 - 4 + 2 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s17 = "%random% + %random% == %random% + 1 - 2 + 2 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s18 = "%random% + %random% == %random% + 1 - 2 + 5 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s19 = "%random% + %random% == %random% + 1 - 2 + 3 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
      $s20 = "%random% + %random% == %random% + 1 - 4 + 2 & %random% + %random% == %random% + 1 - 2 + 3  & %random% + %random% == %random% + 1" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_asd_installer__installer_10 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files asd.bat, installer_.bat, installer.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "6e5f4057a81b07cd68f83fa109c4ad4ddc39615643b8a7005da6e22498ed1fd6"
      hash2 = "2b6a513badc7dfb127f8b63acd7fcadae3d498d11176706ebfe6192fd242c696"
      hash3 = "2caa4b0b35816d523995705bd901a07e0a94e952ec514d83f63159495d7f6041"
   strings:
      $x1 = "    echo UAC.ShellExecute \"cmd.exe\", \"/c %~s0 %params%\", \"\", \"runas\", 1 >> \"%temp%\\getadmin.vbs\"" fullword ascii
      $s2 = "Powershell -Command \"Set-MpPreference -ExclusionExtension exe\"" fullword ascii
      $s3 = "    echo Set UAC = CreateObject^(\"Shell.Application\"^) > \"%temp%\\getadmin.vbs\"" fullword ascii
      $s4 = "    \"%temp%\\getadmin.vbs\"" fullword ascii
      $s5 = "    del \"%temp%\\getadmin.vbs\"" fullword ascii
      $s6 = ">nul 2>&1 \"%SYSTEMROOT%\\system32\\cacls.exe\" \"%SYSTEMROOT%\\system32\\config\\system\"" fullword ascii
      $s7 = "installer.exe" fullword ascii
      $s8 = "REM --> If error flag set, we do not have admin." fullword ascii
      $s9 = "REM  --> Check for permissions" fullword ascii
      $s10 = "cd %TEMP%" fullword ascii
      $s11 = "if '%errorlevel%' NEQ '0' (" fullword ascii
      $s12 = ") else ( goto gotAdmin )" fullword ascii
      $s13 = "    pushd \"%CD%\"" fullword ascii
      $s14 = "    exit /B" fullword ascii
      $s15 = ":--------------------------------------" fullword ascii
      $s16 = ":-------------------------------------" fullword ascii
      $s17 = "    CD /D \"%~dp0\"" fullword ascii
   condition:
      ( uint16(0) == 0xfeff and filesize < 2KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_rolimons_ExecFix_MAS_fucklove_CharmBootstrapper_MinesPredictor_thermia_s_gen_wcarrpt_11 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files rolimons.bat, ExecFix.bat, MAS, fucklove.bat, CharmBootstrapper.bat, MinesPredictor.bat, thermia.bat, s, gen.bat, wcarrpt.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "ad295f3c00cd620318a10b02dc281eee423dfa414f94e2e043908097aaa72e71"
      hash2 = "e3395066a76b5eb8ef6845cde015689c6f9fc976bb08895a4f1f58bee245cbca"
      hash3 = "bd48fe7bacdfb6cb2c32140f720090c4146d82b5eea4bd77556f6bccd4b6adb9"
      hash4 = "8ad70d28d6cb914ddf0dfa0f4e45d1d45cba08a889cb53fb01157ee63eea6073"
      hash5 = "bffd3fbf9a0dd4033796dc80cec61ec4f1d70781623dc5a528c8130a374b48f6"
      hash6 = "35204563561d2a8670cc4fd3e97954a8dba7d3bfc9309b64a1c261aa32b5aee6"
      hash7 = "810b4890b3bd400291ce383c47b88e838378cc0812cec087fda7e9aa76c74791"
      hash8 = "7b43d6d68d3371bf3057c8baab0f3be99db016504bbacc2342e2dd87dfdb11be"
      hash9 = "e5058e10fde17418d38b21339ebb2eb8065d0b34218349bf2f37c3253afe0c4c"
      hash10 = "5d7642b9d233e44586fbbb1b564326e3419bb35e932c2241ec14f937bc42d135"
   strings:
      $s1 = "ayYSuyxUAXusgzgagsfxYAGdsgAHXDFAhadfAHXGa%%axaxaxaxa% /b \" " fullword ascii
      $s2 = "%VXoVQxfIaOJXTyD%%jzFkYEKsIPzUeDP%%GylXUiQxhaaroXA% %BPsLUUIYTkQPcoH%%eUKBFkSAMhSUbvx%%oZVTJCTnZNiBMRX%%teZUzedSpJhJmOP% %OWpXvr" ascii
      $s3 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"shAxhAGDJahADA%XzAdxACashaAUXGaidhAGDYAYX" ascii
      $s4 = "%sdJA%%sdJA% exit /b" fullword ascii
      $s5 = "F%%QLLcMDKTYaBhkcJ%" fullword ascii
      $s6 = "OTJBnSY%%WUgVJbSOgvisABf%%PjiFeKkHlKpYTxT%%DjywNEDpIQiNVVe%%wrGlNqPlHsmAjEq%%cZZahdgAJABDGFHJSNBVFDGHanbcgshJAKndbvGHAJKCNBVbnam" ascii
      $s7 = "Ax0X%HyQakbZUERJmWaF%%nEdJMgecmMNQLsd%%yQZemnpdMjqMSPi%" fullword ascii
      $s8 = "GpLAR%%CdkdbIHfjqiRuaC%%DOAqpdyQsXxYJtp%%JNivdOkKtwZGVJj%%IZvUwzSlBZWOPKd%%IJqxeZEYYZDCdvY%%VYwsxFQEzXWSYDF%%HyQakbZUERJmWaF%_0x" ascii
      $s9 = "bsH%e_0xAx0Xoader.v%eWCOIDPtkzyJXnD%" fullword ascii
      $s10 = "%xjaAisaJAsjAiA% %gfZjNlxCXgARywb% %rNtVUcONIcjnXpg% %qCNVXxvwPfdnmuF%%XzxfNWRPIJVWsfE%%WiQHwUvDGraEgDD%%TbFnnkNqzjwWnOi% %fVKrI" ascii
      $s11 = "%xjaAisaJAsjAiA% %gfZjNlxCXgARywb% %qCNVXxvwPfdnmuF%%fkFzmwUtEypcmIL%%XRbjHVRvxjUfwxZ%%MhhBkpzMwZvKFUD% %uvhODPDhzLKvroK%%kHkzcm" ascii
      $s12 = "set \"cZZahdgAJABDGFHJSNBVFDGHanbcgshJAKndbvGHAJKCNBVbnamjJSHNFNManbdvbNAMJHCGBBnamJSHSDBVDBXNJhagbvfdbncmjhbgvBANMCJBVCSBnajhgb" ascii
      $s13 = "set \"cZZahdgAJABDGFHJSNBVFDGHanbcgshJAKndbvGHAJKCNBVbnamjJSHNFNManbdvbNAMJHCGBBnamJSHSDBVDBXNJhagbvfdbncmjhbgvBANMCJBVCSBnajhgb" ascii
      $s14 = "vcDBSAGVhajnbvdcfbsnhfafGHXNCBVSaAAaAaAa=_0xAx0Xoade\"" fullword ascii
      $s15 = "jJSHNFNManbdvbNAMJHCGBBnamJSHSDBVDBXNJhagbvfdbncmjhbgvBANMCJBVCSBnajhgbdvcDBSAGVhajnbvdcfbsnhfafGHXNCBVSaAAaAaAa%%ijRvhpAkIDZPlf" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_wasp_thermia_12 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files wasp.bat, thermia.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "fd02c1fc0353d13650ff1e60b0a50a95278f13d599ea5849ac23960e323b9345"
      hash2 = "810b4890b3bd400291ce383c47b88e838378cc0812cec087fda7e9aa76c74791"
   strings:
      $s1 = "AABFM9uFwHUUSIuEJOgAAABBD7cEREGLHIZIA9+F7XQNTIuEJPAAAABIhdt0t0yLlCTgAAAASDveD4KiAAAAQYuEP4wAAABIA8ZIO9gPg44AAABFi8NEOBt0HkGD+Dxz" ascii
      $s2 = "AQAAEQ4N3RBRTm1DAUAAHQiSI2FsAAAAMdEJCgAAQAAQYPJ/0iJRCQgTIvHM9Izyf9WcEU5tQwFAABIjY2wAAAASA9Ez//T627/0+tqTY2FDAQAAEE4OHQuSI2FsAAAA" ascii
      $s3 = "9joZQ8AAEyLhSgDAACFwA+EjAAAAIXbddJMi60YAwAATYXAdFMPt0WmvwDAAABIi0wkYESLx0iNFIBIweID/1ZQSItEJFhIhcB0DItV9ESLx0iLyP9WUP+WsAAAAEiLl" ascii
      $s4 = "UgEAAExjejxBi4QXiAAAAIXAD4Q+AQAASI00AkSLdhxEi24gTAPyRItmJEwD6kwD4k2FwA+EDAEAAItuGIXtD4QRAQAAjUX/SYvQQYtMhQCL6EgDz0iJhCToAAAA6NAG" ascii
      $s5 = "wA+IzgEAAEmLTjhIjVQkUEiLAf+QkAAAAIXAD4iGAwAASItMJFBMjUQkSEGL1/+TIAEAAEiLTCRQTI1EJERBi9f/kygBAACLRCREK0QkSEEDxw+EJgEAAEGNTQxFi8cz" ascii
      $s6 = "4lBKItEJAiDZgQAiUYsXsMzwMIEAFWL7IPsLDPAVmogUIlF9IlF+IlF/I1F1FDoiykAAIt1DI1N1IPEDIsGUVb/UAyFwHUSiwaNTfxRjU34UY1N9FFW/1AQM8BeycIIA" ascii
      $s7 = "8AVnUnaAAAAAhqQI1EJFhQVmgfAA8AjUQkXFD/kyABAACFwA+FvAcAAOt6VlJWUWgAAACAV/9TYIv4g///D4SiBwAAhf8PhJoHAACNRCQ8D1fAUFdmDxNEJET/U2SFwA" ascii
      $s8 = "IlYCEiJcBBIiXgYTIlwIFVIi+xIg+xAigFBg87/g2X0AEUzyYgCM/9IjUIBSIvaSIlF6EWL3kiNQQFIiUXgjXcBSI1N4Oj2AQAAhcAPhKoBAABIjU3g6OUBAACFwA+En" ascii
      $s9 = "SgDAABIi8j/liACAABIi0wkaP+W8AAAAEWLhSQFAABJjY0oBQAAM9Lowg4AAEiBxMgDAABBX0FeQV1BXF9eW13DQw+3BGaLHIdJA9gPhGf///9Mi60YAwAARTP2SY29D" ascii
      $s10 = "GEGLwIoMGIhMBCCA+S50CUH/wEU4HBh14kGNQAGL0MZEBCBkQY1AAsZEBCBsQY1AA8ZEBCBsQY1ABEyNBBpEiFwEIEGL00U4GHQXg/o/cxKLyv/CQooEAYhEDGBGOBwC" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_ExecFix_3_ExecFix_2_built_agbcfdxdfsdf_ExecFix_4_2fa_RobloxDowngrader_13 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files ExecFix-3.bat, ExecFix-2.bat, built-agbcfdxdfsdf.bat, ExecFix-4.bat, 2fa.bat, RobloxDowngrader.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "28867e19cd8669a1f570d41d3a8cf829c989931579c74d0278e31bfec4f03049"
      hash2 = "c9f3f1d7e7d8b6cb5630018c3bdc9ec9c5d069b47aabe3ddda630c93b2e0ede4"
      hash3 = "75b768ef203659bcc8134b36689732adbd2a50fa5a522270042026a17a1a2bfb"
      hash4 = "7c51cb0ae8f3e5c72bb09c67aafd5d68dc9cc01d222ba1fc2f1d3eb8672ab287"
      hash5 = "59cbabc323acffe31b9461a1bd5c584bc0cc19ddb74fd2e72da3fcf49ba86679"
      hash6 = "aa8af03833ca5030045f2937ccd1361217fa8515e85bfb63dbcfcc5162273a84"
   strings:
      $s1 = "%VXoVQxfIaOJXTyD%%jzFkYEKsIPzUeDP%%GylXUiQxhaaroXA% %BPsLUUIYTkQPcoH%%eUKBFkSAMhSUbvx%%oZVTJCTnZNiBMRX%%teZUzedSpJhJmOP% %OWpXvr" ascii
      $s2 = "OTJBnSY%%WUgVJbSOgvisABf%%PjiFeKkHlKpYTxT%%DjywNEDpIQiNVVe%%wrGlNqPlHsmAjEq%%ijRvhpAkIDZPlfF%%QLLcMDKTYaBhkcJ%" fullword ascii
      $s3 = "GpLAR%%CdkdbIHfjqiRuaC%%DOAqpdyQsXxYJtp%%JNivdOkKtwZGVJj%%IZvUwzSlBZWOPKd%%IJqxeZEYYZDCdvY%%VYwsxFQEzXWSYDF%%HyQakbZUERJmWaF%%nE" ascii
      $s4 = "%xjaAisaJAsjAiA% %gfZjNlxCXgARywb% %qCNVXxvwPfdnmuF%%fkFzmwUtEypcmIL%%XRbjHVRvxjUfwxZ%%MhhBkpzMwZvKFUD% %uvhODPDhzLKvroK%%kHkzcm" ascii
      $s5 = "dJMgecmMNQLsd%%yQZemnpdMjqMSPi%" fullword ascii
      $s6 = "%xjaAisaJAsjAiA% %gfZjNlxCXgARywb% %rNtVUcONIcjnXpg% %qCNVXxvwPfdnmuF%%XzxfNWRPIJVWsfE%%WiQHwUvDGraEgDD%%TbFnnkNqzjwWnOi% %fVKrI" ascii
      $s7 = "bsH%%uSVfodDOmLBLAZh%%eWCOIDPtkzyJXnD%" fullword ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_ExecFix_2_RobloxDowngrader_14 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files ExecFix-2.bat, RobloxDowngrader.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "c9f3f1d7e7d8b6cb5630018c3bdc9ec9c5d069b47aabe3ddda630c93b2e0ede4"
      hash2 = "aa8af03833ca5030045f2937ccd1361217fa8515e85bfb63dbcfcc5162273a84"
   strings:
      $s1 = "%AoziAsoApppsdAJzhGAahjXHHagHGSHFahJAHjshjHJhajHAJhsjhJAHjahvxgvGAVGcdAGgavgsvdgAVG% \"shAxhAGDJahADA%XzAdxACashaAUXGaidhAGDYAYX" ascii
      $s2 = "ayYSuyxUAXusgzgagsfxYAGdsgAHXDFAhadfAHXGa%exit /b \" " fullword ascii
      $s3 = "UkEQf/USIvwSIXAD4T0AAAAQbgwBQAASIvTSIvI6KIdAACLQwiNSP1BO852GoP4AnVdSI2WKAUAAEiNiygFAADoAxsAAOtFRIuDJAUAAEyNiygFAAAPt8hIjZYoBQAAZ" ascii
      $s4 = "IXJdCVEi4dYDQAAM9LoshwAAEiLj2ANAABEi8Yz0kH/10iDp2ANAAAARIsHM9KLnzACAABIi8/oiBwAAESLxjPSSIvPQf/Xg/sCdQQzyf/VM8Dpsvz//8xIiVwkCFVWV" ascii
      $s5 = "3AFAAB0MkiLz+hW7f//hcB1DYO/cAUAAAIPhEYBAABIi8/oae7//4XAdQ2Dv3AFAAACD4QtAQAARDlzCA+ErQAAAIuTJAUAADPJSIHCLxUAAEG4ADAAAEiB4gDw//9Ej" ascii
      $s6 = "kErzrgAAQAAZgvISI2EJLABAABIiUQkKIuDIAUAAIlEJCD/lwACAACFwHV5SIveiwuNQf1BO8Z2UI1B/0E7xnYVjUH7QTvGd0tIi9NIi8/oqA8AAOs+TI1EJDBIi9NIi" ascii
      $s7 = "8/oYvr//4XAdBBMjUQkMEiL00iLz+ieAAAASI1UJDBIi8/o0fT//+sLSIvTSIvP6LQEAACDvzACAAADdQjr/kG+AQAAAIuHIAkAAL4AwAAAg+gCQTvGdzFIi49gDQAAS" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_RepairTool_wcarrpt_15 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files RepairTool.bat, wcarrpt.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "d4ea9cd7f63d22e929c39fb298d3d0781d232881b2e4a34e200a9b2d72af2e57"
      hash2 = "5d7642b9d233e44586fbbb1b564326e3419bb35e932c2241ec14f937bc42d135"
   strings:
      $s1 = "AABIi40oAwAATWNnPEwD4UyJZCR4hcB0Cz0DAABAD4WaBwAASIXJD4SRBwAAQDg7dGVIi1QkUEyNjRADAAC/BAAAAESLx/9WYEmNXlREi8+LEzPJQbgAMAAASIlcJHD/" ascii
      $s2 = "JiwzP/5MwAQAATI1FwGaJdcBIjZV4AgAASIlFyEiLz/+TEAEAAESL8IXAeQtIi8//kxgBAAAz/4uNeAIAAEEDzImNeAIAADtMJEBys0WF9nhSSItNkEiNVfBIiVQkMA9" ascii
      $s3 = "kRCtEJEhBA8cPhCYBAABBjU0MRYvHM9L/kwgBAABMjYYMBAAAM9JIi/hFOCgPhKAAAABIjUUQQb8AAQAARIl8JChBg8n/M8lIiUQkIP9TcEiNVCRASI1NEP+T+AAAAES" ascii
      $s4 = "XwEiNVaAPKUWg8g8QRYhFM8lIiwlBuBgBAABIiXwkKEiJVCQgSYvV8g8RRbBIiwH/kMgBAABIhf90CUiLz/+TGAEAAEiLfCRYSYvN/5M4AQAASIvP/5M4AQAAQb8BAAA" ascii
      $s5 = "4D4SrAAAASI1FEESJfCQoRYvMSIlEJCAz0jPJ/1NwSI1UJEBIjU0Q/5P4AAAARItEJECNTwwz0kyL+P+TCAEAAEiL+EiFwHRpg6V4AgAAAIN8JEAAdlszyY1xCESNYQF" ascii
      $s6 = "LRCRAuQggAABmiUwkYDPSQY1NCEyL+P+TCAEAAEiJRCRoRImteAIAAEQ5bCRAdjtBi81FjWUBSYsMz/+TMAEAAEiLTCRoSI2VeAIAAEyLwP+TEAEAAIuNeAIAAEEDzIm" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_RepairTool_fucklove_CharmBootstrapper_retrac_fixer_loader_ExecFix_2_RobloxDowngrader_wcarrpt_16 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files RepairTool.bat, fucklove.bat, CharmBootstrapper.bat, retrac_fixer_loader.bat, ExecFix-2.bat, RobloxDowngrader.bat, wcarrpt.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "d4ea9cd7f63d22e929c39fb298d3d0781d232881b2e4a34e200a9b2d72af2e57"
      hash2 = "8ad70d28d6cb914ddf0dfa0f4e45d1d45cba08a889cb53fb01157ee63eea6073"
      hash3 = "bffd3fbf9a0dd4033796dc80cec61ec4f1d70781623dc5a528c8130a374b48f6"
      hash4 = "38aa08661729dd3c2ae3c1fb98f85f6aa4ff5e7385b0db2a65e9e85747848ad8"
      hash5 = "c9f3f1d7e7d8b6cb5630018c3bdc9ec9c5d069b47aabe3ddda630c93b2e0ede4"
      hash6 = "aa8af03833ca5030045f2937ccd1361217fa8515e85bfb63dbcfcc5162273a84"
      hash7 = "5d7642b9d233e44586fbbb1b564326e3419bb35e932c2241ec14f937bc42d135"
   strings:
      $s1 = "CC5AAEAAFD" ascii
      $s2 = "4DAABED7dF" ascii
      $s3 = "BAAC5BAEAA" ascii
      $s4 = "AAC5BAEAAE" ascii
      $s5 = "AB0DcdEDcA" ascii
      $s6 = "BAAAA6ecAAAB" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_ExecFix_4_2fa_17 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files ExecFix-4.bat, 2fa.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "7c51cb0ae8f3e5c72bb09c67aafd5d68dc9cc01d222ba1fc2f1d3eb8672ab287"
      hash2 = "59cbabc323acffe31b9461a1bd5c584bc0cc19ddb74fd2e72da3fcf49ba86679"
   strings:
      $s1 = "tV42EJAABAABQjYMRBgAAUFPoyQIAAIPEDI2EJAABAABQ/5OwAAAAi0wkEIv4agJXUYsR/1IgV4vw/5O0AAAAX4X2dSeLRCQQM/ZWVlaLCFZWVlZWVVD/URSFwHUQi0Q" ascii
      $s2 = "LRwSLd/wDRCQ4A3QkFFBW6NUQAAAPtgaNfyiDxAyJR9APt0UGQzvYctSLnCRUAwAAi2wkLIt0JByLVCQQi/orfTSDfCQkAA+EwgAAAIX/D4S6AAAAi4agAAAAjQwQA0Q" ascii
      $s3 = "Q8D7dEcP6LdIUAA/IPhLQAAACLrCRYAwAAjb0MBAAAgD8AdDGDvQwFAAAAdBKNhCRMAQAAUFdT6OEEAACDxAyDvQwFAAAAjYQkTAEAAA9Ex1D/1utZ/9brVY2FDAQAAI" ascii
      $s4 = "kDGoCUIsI/1EU6wIz9otEJBBQiwj/UQiLRCQMUIsI/1Eci0QkDFCLCP9RCIuDWA0AAI0ERQIAAABQVlXo9ggAAIPEDGgAwAAAVlX/U0BeXVuBxPQCAADDgeyUAAAAZKE" ascii
      $s5 = "AAFBqA1aNg7AIAABQ/5PwAAAAhcAPhdEAAACLTCQMjUQkEFCNgwAJAABQixFR/xKFwA+FoAAAAItEJBBQiwj/UQyFwA+FhAAAAItMJAyNVCQUiUwkNFJRiwH/UAyFwHV" ascii
      $s6 = "QOAQAAi3QRGIX2D4QCAQAAi0QRII1+/4tsERwDwotMESQD6gPKiUwkPI08uIuMJFgDAACLB4HBDAMAAAPCUVDoBQwAAItUJBhZWYXAdA9qBFgr+IPuAXXU6ckAAACLRC" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_ExecFix_wasp_MinesPredictor_thermia_Valex_Bootstrapper_gen_18 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files ExecFix.bat, wasp.bat, MinesPredictor.bat, thermia.bat, Valex-Bootstrapper.bat, gen.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "e3395066a76b5eb8ef6845cde015689c6f9fc976bb08895a4f1f58bee245cbca"
      hash2 = "fd02c1fc0353d13650ff1e60b0a50a95278f13d599ea5849ac23960e323b9345"
      hash3 = "35204563561d2a8670cc4fd3e97954a8dba7d3bfc9309b64a1c261aa32b5aee6"
      hash4 = "810b4890b3bd400291ce383c47b88e838378cc0812cec087fda7e9aa76c74791"
      hash5 = "99b88f4d8c0ce33dbc067246511491545cc4736d4593c1ff3045ef025fbb487d"
      hash6 = "e5058e10fde17418d38b21339ebb2eb8065d0b34218349bf2f37c3253afe0c4c"
   strings:
      $s1 = "DAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */
      $s2 = "3AFAAABdC5" ascii
      $s3 = "AcdBFAcAAABB" ascii
      $s4 = "dACAAAEAAAA" ascii
      $s5 = "b8BAAAA60a5CCAAAE" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_DROPPER_AUG25_built_agbcfdxdfsdf_ExecFix_4_19 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files built-agbcfdxdfsdf.bat, ExecFix-4.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "75b768ef203659bcc8134b36689732adbd2a50fa5a522270042026a17a1a2bfb"
      hash2 = "7c51cb0ae8f3e5c72bb09c67aafd5d68dc9cc01d222ba1fc2f1d3eb8672ab287"
   strings:
      $s1 = "BIiWwkGEiJdCQgV0FWQVdIg+wwM/Yz7UUz9kiL+kyL+UKKTD0AhMl0FIP9QHQPiEw0IP/F/8aD/hB1Z+tTi8ZIjVwkIEgD2EG4EAAAAEiLy0QrxjPS6M0EAADGA4CD/g" ascii
      $s2 = "RIvYQYP6G3LNiUwkKESJRCQsSItEJChIg8QQW8NFhckPhEUBAABIiVwkCEiJdCQQSIl8JBhVQVRBVkiL7EiD7BBMi9lIjUXwTCvYTI1yD0mL+EG8EAAAAEiNRfBJO8Z3" ascii
      $s3 = "LSIlF4CPOg8ECQdHrdCFIi1XoRYvDSffYQYoEEIgCSAPWQQPOdfJIiVXo6fwAAACL/un1AAAARIvWSI1N4OgyAQAASI1N4EaNFFDoJQEAAIXAdeZFhcl1SEGD+gJ1QkS" ascii
      $s4 = "sAwgQAuAFAAIDCCABWV+g+JQAAi3QkELmtEUAAv3s2QAArzwPBiw6JAegjJQAAuR8RQAArzwPBiw6JQQToECUAALkMEkAAK88DwYsOiUEI6P0kAAC5LhFAACvPA8GLDo" ascii
      $s5 = "lBDOjqJAAAuS4RQAArzwPBiw5fiUEQi0QkCINmBACJRghew4tMJAyFyXUHuANAAIDrTVOLXCQMM9JWi3QkDFeLfgiLhJcwCAAAOwSTdQhCg/oEde7rFDPSi4SX8AgAAD" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 8000KB and ( all of them )
      ) or ( all of them )
}

