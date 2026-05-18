/*
   YARA Rule
   Author: DeTraced Security
   Date: 2025-10-17
   Identifier: MAL_BETRAY_DROPPER_AUG25
   Reference: https://detraced.org/posts/infostealer-turned-ransomware
*/

rule MAL_BETRAY_DROPPER_AUG25_fix {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - file fix.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      yarahub_author_twitter: @DeTraced-Sec
      yarahub_author_email: detraced-sec@proton.me
      yarahub_uuid: 591e447e-c8f9-4f09-9974-26fddb131542
      yarahub_license: CC BY 4.0
      yarahub_rule_matching_tlp: TLP:WHITE
      yarahub_rule_sharing_tlp: TLP:WHITE
      yarahub_reference_md5: 221bb43b8065c5feb6d1090955e79089
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