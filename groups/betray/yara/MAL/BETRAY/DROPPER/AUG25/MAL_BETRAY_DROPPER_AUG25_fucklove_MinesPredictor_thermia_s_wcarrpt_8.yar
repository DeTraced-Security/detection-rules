/*
   YARA Rule
   Author: DeTraced Security
   Date: 2025-10-17
   Identifier: MAL_BETRAY_DROPPER_AUG25
   Reference: https://detraced.org/posts/infostealer-turned-ransomware
*/

rule MAL_BETRAY_DROPPER_AUG25_fucklove_MinesPredictor_thermia_s_wcarrpt_8 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files fucklove.bat, MinesPredictor.bat, thermia.bat, s, wcarrpt.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      yarahub_author_twitter = @DeTraced-Sec
      yarahub_author_email = detraced-sec@proton.me
      yarahub_uuid = 092b6275-18e9-40b6-9b83-0f577b11cc03
      yarahub_license = CC BY 4.0
      yarahub_rule_matching_tlp = TLP:WHITE
      yarahub_rule_sharing_tlp = TLP:WHITE
      yarahub_reference_md5 = b69bb37ca650cd2f741fa0b9bb330522
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