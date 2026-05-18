/*
   YARA Rule
   Author: DeTraced Security
   Date: 2025-10-17
   Identifier: MAL_BETRAY_DROPPER_AUG25
   Reference: https://detraced.org/posts/infostealer-turned-ransomware
*/

rule MAL_BETRAY_DROPPER_AUG25_ExecFix_wasp_MinesPredictor_thermia_Valex_Bootstrapper_gen_18 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files ExecFix.bat, wasp.bat, MinesPredictor.bat, thermia.bat, Valex-Bootstrapper.bat, gen.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      yarahub_uuid: e68b4afb-7dfb-4b8e-a45b-c61c4bd9ffda
      yarahub_license: CC BY 4.0
      yarahub_rule_matching_tlp: TLP:WHITE
      yarahub_rule_sharing_tlp: TLP:WHITE
      yarahub_reference_md5: 3562943cfdab88725298affae3f9b074
      hash1 = "e3395066a76b5eb8ef6845cde015689c6f9fc976bb08895a4f1f58bee245cbca"
      hash2 = "fd02c1fc0353d13650ff1e60b0a50a95278f13d599ea5849ac23960e323b9345"
      hash3 = "35204563561d2a8670cc4fd3e97954a8dba7d3bfc9309b64a1c261aa32b5aee6"
      hash4 = "810b4890b3bd400291ce383c47b88e838378cc0812cec087fda7e9aa76c74791"
      hash5 = "99b88f4d8c0ce33dbc067246511491545cc4736d4593c1ff3045ef025fbb487d"
      hash6 = "e5058e10fde17418d38b21339ebb2eb8065d0b34218349bf2f37c3253afe0c4c"
   strings:
      $s1 = "DAAAAAAAAAAAA" ascii /* base64 encoded string  */
      $s2 = "3AFAAABdC5" ascii
      $s3 = "AcdBFAcAAABB" ascii
      $s4 = "dACAAAEAAAA" ascii
      $s5 = "b8BAAAA60a5CCAAAE" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}