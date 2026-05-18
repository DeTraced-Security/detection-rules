/*
   YARA Rule
   Author: DeTraced Security
   Date: 2025-10-17
   Identifier: MAL_BETRAY_DROPPER_AUG25
   Reference: https://detraced.org/posts/infostealer-turned-ransomware
*/

rule MAL_BETRAY_DROPPER_AUG25_ExecFix_4_2fa_17 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files ExecFix-4.bat, 2fa.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      yarahub_author_twitter: @DeTraced-Sec
      yarahub_author_email: detraced-sec@proton.me
      yarahub_uuid: ecd94a3e-5609-4430-9931-67adf7d63d6e 
      yarahub_license: CC BY 4.0
      yarahub_rule_matching_tlp: TLP:WHITE
      yarahub_rule_sharing_tlp: TLP:WHITE
      yarahub_reference_md5: a1c042062ab64e5aec09a844736e724d
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
