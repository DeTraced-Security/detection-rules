/*
   YARA Rule
   Author: DeTraced Security
   Date: 2025-10-17
   Identifier: MAL_BETRAY_DROPPER_AUG25
   Reference: https://detraced.org/posts/infostealer-turned-ransomware
*/

rule MAL_BETRAY_DROPPER_AUG25_ExecFix_3_ExecFix_2_built_agbcfdxdfsdf_ExecFix_4_2fa_RobloxDowngrader_13 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files ExecFix-3.bat, ExecFix-2.bat, built-agbcfdxdfsdf.bat, ExecFix-4.bat, 2fa.bat, RobloxDowngrader.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      yarahub_author_twitter: @DeTraced-Sec
      yarahub_author_email: detraced-sec@proton.me
      yarahub_uuid: 628bd841-e306-4c00-8251-b24dff58761c
      yarahub_license: CC BY 4.0
      yarahub_rule_matching_tlp: TLP:WHITE
      yarahub_rule_sharing_tlp: TLP:WHITE
      yarahub_reference_md5: 18bd43b2dfad0c247148db1afdf8462e
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