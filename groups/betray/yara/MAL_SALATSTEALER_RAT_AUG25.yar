/*
   YARA Rule Set
   Author: DeTraced Security
   Date: 2025-10-17
   Identifier: MAL_SALATSTEALER_RAT_AUG25
   Reference: https://detraced.org/posts/infostealer-turned-ransomware
*/

/* Rule Set ----------------------------------------------------------------- */

rule MAL_SALATSTEALER_RAT_AUG25_verbal {
   meta:
      description = "MAL_SALATSTEALER_RAT_AUG25 - file verbal.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "871f032930195376ec3985ac018b9a0c4c8a329efacd4e0b6d3cb57229a8cc7e"
   strings:
      $s1 = "Ym1neT9dt" fullword ascii /* base64 encoded string 'bmgy?]' */
      $s2 = "* k]T2" fullword ascii
      $s3 = "`G:\"R5|z" fullword ascii
      $s4 = "evsKeYYt" fullword ascii
      $s5 = "-w+Yce:\\" fullword ascii
      $s6 = "qf -1mk|" fullword ascii
      $s7 = "1{vHn!." fullword ascii
      $s8 = "OAQmyN6" fullword ascii
      $s9 = "yasepb" fullword ascii
      $s10 = "\\TzMH!" fullword ascii
      $s11 = "7yqx%G%" fullword ascii
      $s12 = "UWfJTj1" fullword ascii
      $s13 = "te%I%{Q_" fullword ascii
      $s14 = "flgjhc" fullword ascii
      $s15 = "+ mAq7" fullword ascii
      $s16 = " -_08d" fullword ascii
      $s17 = "fsxxfi" fullword ascii
      $s18 = "7d+ :n" fullword ascii
      $s19 = "NVcPII4" fullword ascii
      $s20 = "1cf * n" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      8 of them
}

