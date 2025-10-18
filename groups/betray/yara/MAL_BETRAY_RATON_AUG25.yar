/*
   YARA Rule Set
   Author: DeTraced Security
   Date: 2025-10-17
   Identifier: MAL_BETRAY_RATON_AUG25
   Reference: https://detraced.org/posts/infostealer-turned-ransomware
*/

rule MAL_BETRAY_RATON_AUG25 {
   meta:
      description = "MAL_BETRAY_RATON_AUG25 - from files Stuff.dll, Raton.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "9c33e6e0c5dd37d9b7539e234110bd2024fefe6279c251d9b7939d5103f88745"
      hash2 = "003cef0a5ed05c5105020e33b770ded3aec978801b7823f5bd58b46662523cf4"
   strings:
      $s1 = ".NETFramework,Version=v4.7.2" fullword ascii
      $s2 = "GetAsBoolen" fullword ascii
      $s3 = "GetAsInteger" fullword ascii
      $s4 = "BytesToString" fullword ascii
      $s5 = "Unpacc" fullword ascii
      $s6 = "MD5_STRING" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( all of them )
      ) or ( all of them )
}

