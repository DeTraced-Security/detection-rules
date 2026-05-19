/*
   YARA Rule
   Author: DeTraced Security
   Date: 2025-10-17
   Identifier: MAL_BETRAY_DROPPER_AUG25
   Reference: https://detraced.org/posts/infostealer-turned-ransomware
*/

rule MAL_BETRAY_DROPPER_AUG25_heyhaveagoodday {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - file heyhaveagoodday.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      yarahub_author_twitter = @DeTraced-Sec
      yarahub_author_email = detraced-sec@proton.me
      yarahub_uuid = 5412c906-2b0b-4e52-bc0f-44e79a7829b9
      yarahub_license = CC BY 4.0
      yarahub_rule_matching_tlp = TLP:WHITE
      yarahub_rule_sharing_tlp = TLP:WHITE
      yarahub_reference_md5 = d46e90b910a6276a03d1559c58352833
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