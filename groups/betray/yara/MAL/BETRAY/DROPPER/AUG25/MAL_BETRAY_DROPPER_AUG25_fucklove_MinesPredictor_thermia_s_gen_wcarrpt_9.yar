/*
   YARA Rule
   Author: DeTraced Security
   Date: 2025-10-17
   Identifier: MAL_BETRAY_DROPPER_AUG25
   Reference: https://detraced.org/posts/infostealer-turned-ransomware
*/

rule MAL_BETRAY_DROPPER_AUG25_fucklove_MinesPredictor_thermia_s_gen_wcarrpt_9 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files fucklove.bat, MinesPredictor.bat, thermia.bat, s, gen.bat, wcarrpt.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      yarahub_uuid: e34b46a3-6809-4994-bd70-6cc25d66e975
      yarahub_license: CC BY 4.0
      yarahub_rule_matching_tlp: TLP:WHITE
      yarahub_rule_sharing_tlp: TLP:WHITE
      yarahub_reference_md5: b69bb37ca650cd2f741fa0b9bb330522
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