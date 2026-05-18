/*
   YARA Rule
   Author: DeTraced Security
   Date: 2025-10-17
   Identifier: MAL_BETRAY_DROPPER_AUG25
   Reference: https://detraced.org/posts/infostealer-turned-ransomware
*/

rule MAL_BETRAY_DROPPER_AUG25_fucklove_wcarrpt_1 {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - from files fucklove.bat, wcarrpt.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      yarahub_uuid: f1876aa0-d0d9-402b-aae5-5ac3c89319a4
      yarahub_license: CC BY 4.0
      yarahub_rule_matching_tlp: TLP:WHITE
      yarahub_rule_sharing_tlp: TLP:WHITE
      yarahub_reference_md5: b69bb37ca650cd2f741fa0b9bb330522
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