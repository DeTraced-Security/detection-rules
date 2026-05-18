/*
   YARA Rule
   Author: DeTraced Security
   Date: 2025-10-17
   Identifier: MAL_BETRAY_DROPPER_AUG25
   Reference: https://detraced.org/posts/infostealer-turned-ransomware
*/

rule MAL_BETRAY_DROPPER_AUG25_l6E {
   meta:
      description = "MAL_BETRAY_DROPPER_AUG25 - file l6E.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      yarahub_author_twitter = @DeTraced-Sec
      yarahub_author_email = detraced-sec@proton.me
      yarahub_uuid = f7d0f2a0-4e56-47b8-bf49-ab5d6ae93f4f
      yarahub_license = CC BY 4.0
      yarahub_rule_matching_tlp = TLP:WHITE
      yarahub_rule_sharing_tlp = TLP:WHITE
      yarahub_reference_md5 = 0c5738f4b8bfcc506d84ba1b3c8b0640
      hash1 = "cad387308c8848492c62cd8e9e45cb127709650167221bbe6a6538387c85be4e"
   strings:
      $s1 = "%aIijVjW%se%iNFDebk%t%QPHLs% \"YL2WG3s=2X2Ptlzt1rxGyOlbqjsZx+xPaXakjINZPLInNV5ctQQ2TmDEbzrIkfuG1GOOwyiYfSvNCxWkoNMThhpRLu3or8TmA" ascii
      $s2 = "%EF4GXw%set \"BNnRf=*') {\" &&s%I68K%et \"tZvRpM=ll /f\"&& %rM1T%set \"vLSwHjhi= '*QEM\"&& %uF9cGArc%se%u4aN1%t%CQYMilQU% \"kv22" ascii
      $s3 = "s%ykIzfG5l%et%xjYgMtt0% \"cxXBb=WxV/+MQ5EWjJg5htA10C9GV9XQlADgNBPVGMymEUc9LaL4iEYYOT14GYn+AvvCoIB1fz5dLUxKK9Nm6SCi1fmzo6PkE7anS8" ascii
      $s4 = "%lXO3%set%AfaI% \"kbGQFic=9e5XRqr7RO4LBJrm5lI1/kcPOxVILriYvoZynd9O/F9mHojq7hOqt7F/K5IAtmJzWinKSxfg5EGVijCxu2AejfPyFfgEg6OcB9dr73" ascii
      $s5 = "%YVYcLg8l%s%zA4U%et \"PDUkjb=HU3M9b7R2QPwzPK7H87Pp44aF5/vKRJz+de8sgfOnENFdAalybo35KVVODAHYlFO+lNt72Bt2Stj0B2+7Wn8EEFT8FX6+Qbae6X" ascii
      $s6 = "s%L0Ncl%e%aYPjrrWp%t \"hVvHT8jv=xeW6b7s9Xia2pSMhnaI5NN/F62iBbh4LvViqeaSZgZQLJpClk+nuoc+K897kEX1nhYVWkLHMZ4Xd6HRcSydrGN0+Ng9vr9GW" ascii
      $s7 = "REm route truly ghost float become write process volume spell erode" fullword ascii
      $s8 = "%aWXZIVF%s%l3H6wo%et%OAb2EkB% \"YpCYb=vrAqJ*%bdOO9u%K8Nm0%mSOj6g%d*isMyI*b%U2Noeho%Z0zsY*l9%S07ipgs%8R*Hx%JLDG%zDRj*UwTg%tJaap%C" ascii
      $s9 = "%uc7t74b1%s%VCJzi1A%e%OI3l%t \"ruzVA5C=+G/3Lnoi1heC7AeTEymhtoF5SBnDfKS+HwUAa1s5RVPu53rSwB3MvagILkX3FtsY5JhOk9eqvyxuhctL7Vy2WDyDu" ascii
      $s10 = "s%vaVNB%e%W8YCh%t%V5Ot% \"YHkLd=X7hMD/vxV5aVP+0s6vXDplZhl+fTu2RuoNNUMSeNG2a14DtJPAAZMh1UM2mrTQgx44mq56fwJtPFdChN153EKeyLYdZVnOk2" ascii
      $s11 = "%BitE8%set \"uK2R=')){for\" && set \"XJNn1nt=n.GetA\" &&se%hiAipPdZ%t \"dwkL=Contai\" &&%UPycjlJ%set%Azy6kZB% \"VeaRKxn4=tring[" ascii
      $s12 = "s%iD64m%et%C3emDPl5% \"NU94ZS=XrENe9N061oAqM3T8536nQUX32x/6GTYGO7I9mh5EKrQwdwLTF/V/gGfUP1Jg+C/Mw6KPbBnmQ8V4pZHiGGn0E5zsDFuQg9uxt" ascii
      $s13 = "%IMfpk%s%sdlg%et%DhyA0X% \"ZDjBNHM9=HDEwAImuXtm88jo50S8RGEzUc11yEtGME9PmOWKU7Q6aN9v6KgJXYeF7/dh9ZICbzLk/qA2IqqlC8AltAxX+hgDEOtGD" ascii
      $s14 = "s%MyxDx%et%P1rP94DV% \"orRy5jF=e]::Get\" && s%f6Yc%et \"BVpJDlqp=Item (\" &&set%WXtYT2KC% \"PycGu=e --h\"&& s%Nelu%et \"pWQHg51=" ascii
      $s15 = "se%U6IdL1p%t%jqq6vT% \"cGgLM=hZigYnYcsoANAuW1xfwgp4orXU/j7aKWsc3EYMFhNdxfMULsssvixmK24WDpNrOkSaXvlzCgVgUVzbmsosU0GLQ9oNAIi1Zdf6R" ascii
      $s16 = "EJ/+RvQbmc21i3/xlKf1GHQfC0y1dFMlBkTzO+ZXjY8zTMp4d51pW98nVsSp7JTP0HCW3NyX5xRcvRsAZt1XrcyixkYB10eh33JspYwdb6LHp85htbT9dDnSN2WdrVoq" ascii
      $s17 = "c92/ZmdK6IjbIn77CU6P5GAq+FMKciDTBaHsuudFkAOlaAUZ6hIbKGEgQ8N9gLfR738AdLldigdfqxtStTCZINOViaPaKBagg2PRW87pGKshD1wnyWxrW8/KlsatKIqI" ascii
      $s18 = "mK77fSuIx1gS2V5PMh4vN1VfK51BedOBI+4vWL7f+iGU3b7YjqnXifyZALoGSVuBufXaZwKu0D2d2ZfKksNAUqIVGazyurFKxo28g74ndAu+TMPgi0zRT//hzRqZU563" ascii
      $s19 = "ySPY68Qd1t/G13ZOHZoJy0QQCIHoUxrsydGfANgKZgZqQgoBt8OhVbX/fbgQJkeih/H9L9xk74dKEYixUvhXClYj6E7Ya9bve0LD5vmtVjeyJNMrlWa6+w/gXL/UGx1a" ascii
      $s20 = "set%JfkF% \"UONki9XN=g4nNCVFox/ilqyQx0Yf2d9pn2siTkUAh7d3/bsCFYgFf7Vn1Kct32m5EinMzdiNoOUs+550OLUst+Ng8Y1lKgNcRDeKzHpQJc4aUs6eF1lw" ascii
   condition:
      uint16(0) == 0x6540 and filesize < 2000KB and
      8 of them
}