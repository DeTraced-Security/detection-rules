/*
   YARA Rule Set
   Author: DeTraced Security
   Date: 2025-10-17
   Identifier: MAL_BETRAY_RAT_AUG25
   Reference: https://detraced.org/posts/infostealer-turned-ransomware
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule MAL_BETRAY_RAT_AUG25_empress {
   meta:
      description = "MAL_BETRAY_RAT_AUG25 - file empress.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "2921f72f4c2a53f6c30d89d2dd6bf055cbff1bc58d67cb89ebdea56b997ff917"
   strings:
      $x1 = "powershell -Command \"$Action = New-ScheduledTaskAction -Execute '%s'; $Trigger = New-ScheduledTaskTrigger -AtLogon; $Settings =" wide
      $x2 = "C:\\Users\\gavin\\source\\repos\\EmpressLoader\\x64\\Release\\EmpressLoader.pdb" fullword ascii
      $s3 = "https://github.com/ArminAyna686/perfectworld/raw/refs/heads/main/tg.exe" fullword wide
      $s4 = "powershell -Command \"Add-MpPreference -ExclusionPath '%s'\"" fullword wide
      $s5 = "powershell -Command \"Add-MpPreference -ExclusionExtension '%s'\"" fullword wide
      $s6 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' public" ascii
      $s7 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' public" ascii
      $s8 = "VCRUNTIME140_1.dll" fullword ascii
      $s9 = "https://pastebin.com/raw/n29h9TLy" fullword wide
      $s10 = "\\defender.exe" fullword wide
      $s11 = "\\windows.exe" fullword wide
      $s12 = "EmpressLoader, Version 1.0" fullword wide
      $s13 = "EMPRESSLOADER" fullword wide
      $s14 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s15 = "\\WindowsSecurityService.lnk" fullword wide
      $s16 = "About EmpressLoader" fullword wide
      $s17 = "EmpressLoader" fullword wide
      $s18 = " *User:* `" fullword wide
      $s19 = "KeyToken='6595b64144ccf1df' language='*' />" fullword ascii
      $s20 = "https://api.telegram.org/bot" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule MAL_BETRAY_RAT_AUG25_obsession {
   meta:
      description = "MAL_BETRAY_RAT_AUG25 - file obsession.my"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "599e1c42e70ef057f1c33e875399cce2ecbe834654506f5317dde81c8b777f38"
   strings:
      $x1 = "     label1 panel1 Form1 pictureBox1 richTextBox1 label2 <Module> COMPILEYOURSELF SizeF mscorlib Form1_Load add_Load Add Synchro" ascii
      $s2 = "   C:\\Users\\whoami\\Desktop\\COMPILEYOURSELF\\obj\\Debug\\COMPILEYOURSELF.pdb " fullword ascii
      $s3 = "value COMPILEYOURSELF.exe set_Size set_AutoSize set_ClientSize ISupportInitialize set_Padding System.Runtime.Versioning GetStrin" ascii
      $s4 = "te TargetFrameworkAttribute AssemblyFileVersionAttribute AssemblyConfigurationAttribute AssemblyDescriptionAttribute Compilation" ascii
      $s5 = ", System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii
      $s6 = "g disposing System.Drawing get_Black button1_Click Label System.ComponentModel Panel ContainerControl Program System Form resour" ascii
      $s7 = "   fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap" ascii
      $s8 = "   fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap" ascii
      $s9 = "eft EndInit BeginInit GraphicsUnit get_Default SetCompatibleTextRenderingDefault ContentAlignment InitializeComponent get_Transp" ascii
      $s10 = "   lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resource" ascii
      $s11 = "   QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
      $s12 = "   lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resource" ascii
      $s13 = "omponentResourceManager EventHandler System.CodeDom.Compiler IContainer set_ForeColor set_BackColor .ctor .cctor System.Diagnost" ascii
      $s14 = "ics System.Runtime.InteropServices System.Runtime.CompilerServices System.Resources COMPILEYOURSELF.Form1.resources COMPILEYOURS" ascii
      $s15 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s16 = "ELF.Properties.Resources.resources DebuggingModes COMPILEYOURSELF.Properties EnableVisualStyles Settings EventArgs get_Controls " ascii
      $s17 = "System.Windows.Forms set_AutoScaleDimensions set_ScrollBars RichTextBoxScrollBars SystemColors components GetObject set_RightToL" ascii
      $s18 = "se Dispose EditorBrowsableState STAThreadAttribute CompilerGeneratedAttribute GuidAttribute GeneratedCodeAttribute DebuggerNonUs" ascii
      $s19 = " 3System.Resources.Tools.StronglyTypedResourceBuilder 4.0.0.0  Y" fullword ascii
      $s20 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule MAL_BETRAY_RAT_AUG25_pedo {
   meta:
      description = "MAL_BETRAY_RAT_AUG25 - file pedo.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "4690de31f6453c6d10e929e4b79401e05b8a6adcf70f8f37d5a257bd97a906d0"
   strings:
      $x1 = ":: 6NMpHQDTKR0AlT@lS5xkax/TQ1sSVbKOWtGMSj2I+ADQp6SFhemCm7WkAAAAAlqvV9rdyq+x98U9OtdE3rjLogE3GZi+OQKZ29yJuDz0DmZ6jrmmQCSpcDa1rqi29" ascii
      $x2 = "rem H4sIAG+bbWgC/+y9B3hURds+fjbJkk0g7FIiAVEiBA2gGI0oIUSzsIGzsKGX0EvoXbILSA1sAmwOi6ggVQGVasNGFUzBFJoQOqggthOCviBKh/3d95xNSCiW732/" ascii
      $s3 = "Zi/gZjD3vrZYN1WskZflr9m1qROMvDGft7UCLICTxmiBZ3AY3YUHE3IU32O97+bWaBVOTRGsbYVVNJPASPZv3RHYcJhu79cvBhlJh9j6xfleLUHCfrLOgInaABdyU+bF" ascii
      $s4 = "+qYCX98xCHaiFUrvLn8d/u0PK50rg8USkEJ9qs+xdeZoJSu3P3ebL97PGgizoF8Clsob4bhjEwTxfqpJHLxoRFMBoEzDdZiEFeFK0hu5014DumpVJh2bzedMcwiBL/eF" ascii
      $s5 = "h63rqqJ5Mzdl/+iRpMdxCVTNXOzLs0Em12UuVuqj6L8T6sP7Sa5TduMpXkxU+kGXsJvVwUa+Hv2wl0iGLh4vKHKKDEXwjWcZIWTxDgHhQjXjaaG/PbvZeUyXAZr5fBtO" ascii
      $s6 = "Iv12V4M6UM1iXi3qId1wYUmh/cW2nQHD6duMPkjhpxXELyJOiS7DTzhDCL5j8yG10gwpVRXfheGYV8wpRy/vc7m4s/F+hd55iwEnXqZSaV/ngJnB6d0rpgl0HrkzwAkr" ascii
      $s7 = "ZlZUZJhlxgKJgu1cLFKWM7h3ouP15eAvW8do0YOzMsq7OVcNhVPCfIRc5lLrdyMLhcs0DwDLLom+D7808QbM+Sys3anrPSmxKqWal5TXQIpRlaIHEkjGXpIG6thZVnA0" ascii
      $s8 = "y79dPFnpA1mpMX9o36Qva/ocUm6rygUIeqXWrDl8E4gjMU6Alas7yxOJwqBr3+y1UHXXnGzvr60eqt34yT78pOCYGlrBFMDLL6GV8tSg5qUws4XP5wElLATSPy+u4gKY" ascii
      $s9 = "XoilOGtz0WzPsFDw7CrV2izgKK3HWPsiQyrbeYFY8xtqwIQlsiPEPgyQ9vpJbI3+nOAah/sQdJPULpzOIqHySfX0Xb4Lh+KcB45ZRYbt8CBteXTnx2X7QvspYx+UX6R2" ascii
      $s10 = "LmtZUrRNJQAUzRCNxEDJbjwBKrvdoAGHqaxZiKKOQRUEIIoIsvtVJrkQiYTLOtyTwjCXeriGDNnMaoEkPQTuYscFHcgZOBiAEbAuqiyqyJRcHMxiKoeYVgELTfCHEcKc" ascii
      $s11 = "l29+xtFsPy2/mxlqnhAkSNWLxIF3jJjle+KxDNgbJ7flr8wFHJRmpB+U1r+IkV+8Hj9OhDqIXJVqS+oBv2K4b4h7mrxVkzOgTCgeThxbra5thx7Jd9KWHn+Gj7A6DUFh" ascii
      $s12 = "znGuoTdHp/HQ/mS11yViYRF3rzxjys9Pmw3EN2Fi8/71y/HkIwhU4s4FGoKZVe4GZZNExU16Vc3yNlGET2sW0SFlmLFSL+rjbYRGGFMFl4ROQdYzeNn9TNbCgdqpmRt9" ascii
      $s13 = "3DWK4WC/YXUg0uKWTqmIMFG58D4rQC+dfbp/6SE9qytS+0rHOxUGQTw4Dt05xxdhkgEyEtdgwsbxOGyseibfveBinPutVF0lOdwP7U8yA/ZM2LHpjmKdJMT8FkPSGiER" ascii
      $s14 = "8wBNiijk1gQAY97gQkAqo6oUuk8fVlbD2yeM0GMzYJiDCeOvC4oSCc/uMXlxnhx+H5LeXSMKTmPapW8EcKZ/jn+0A3Chyzuf9gM4088IT/7FHSPy/DhBdDn+eOiM7B2o" ascii
      $s15 = "7hLkETYFcLJwYWVQ3QliKeyGQlnBjFY4AudJBp1wVqC/KdX5TEqg+1/gTzFaPGsuXPJeUYX4lcCbK+R5GETg+ENOpF5naB7dgyl4Ziu+FoUesU+c+/3TFuXuSReQM9ld" ascii
      $s16 = "HPgR7b3RtEr44JHles7/+mQpqUwF9MZVSx5JNGM6UPHaWoHngpVdneQkKAWNRWvKeyyrGe3uul44eyeyFL6HzFpiojqB5HKsVqpzYab42iLfKq0cYyReZzVpdUghqZc1" ascii
      $s17 = "MWAepfUJgR46mTMPiSLz1M43ucCvZh6i+AtcDwQeWbsUqD/Ob4d+hHEVJiX2DSMu33qkgSEwQOUqNwS3snwUdBo++02qyiZlQ9bcUhOkMcuWCNNEfLOG3Xc6VSBnkHSO" ascii
      $s18 = "74JZXhUCpqS6HODU3LuCG5LGi08xFZvw2I41UpEXeCIlY+0pSLCqi9S0L/3cQaMUNWnVKZahQk9lKsubSyb3jCH4+QniPuz3CuGUlGWCbxTCi4rElO7j2Ilk7r54Ycb4" ascii
      $s19 = "o5E4/Rg7Y5yZ8N93nv3b8+35Jx9yIj0ar6Lx15mInlIQPsFMTrrEYjexeCYVh/cQ4vAKHlkRise7pfE4jgTsnpzyT8TuEvH570E43MF4hSoFh5uCsQpjFXavxu/JGm0C" ascii
      $s20 = "DR/dHFv/raS8GLyX2LFzVBD7zIZerXwVgETjsqEJHpHwhSLKx9wRIFKcGBjtLbm9aQXxNaMeGG/SoUhN9AZPqxVDqU/Xmxk9227QnRUnKTZ5jArecHe4b4iZIkndr7sU" ascii
   condition:
      uint16(0) == 0x6540 and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

rule MAL_BETRAY_RAT_AUG25_2fa_road_2faBeta_uac_6_1_25_0 {
   meta:
      description = "MAL_BETRAY_RAT_AUG25 - from files 2fa.exe, road.exe, 2faBeta.exe, uac.exe, 6-1-25.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "56af25d62871b59803c9b9a31dd8e74796d43733da684f8ee2925dfba0360f7b"
      hash2 = "c8f6f00b8ee92ee530bef1d760e378e85123dc69a146ee247eac2ea4d760a15a"
      hash3 = "5acae9ee314434f35112164ced87d71032d05bd97716719fa0338aee5c6ed67e"
      hash4 = "f2c960225df390a81642300de838bd1c392bdf0e273dd7d4a757ea783c972f13"
      hash5 = "cb8cdc3ba28a9a8d76bd477aa4f0b7e4ef6b97c66a58524db4f717f53ec09891"
   strings:
      $x1 = "Conhost --headless cmd.exe /c taskkill /IM opera.exe /F" fullword wide
      $x2 = "Conhost --headless cmd.exe /c taskkill /IM operagx.exe /F" fullword wide
      $x3 = "Conhost --headless cmd.exe /c taskkill /IM firefox.exe /F" fullword wide
      $x4 = "Conhost --headless cmd.exe /c taskkill /IM brave.exe /F" fullword wide
      $x5 = "Conhost --headless cmd.exe /c taskkill /IM msedge.exe /F" fullword wide
      $x6 = "Conhost --headless cmd.exe /c taskkill /IM chrome.exe /F" fullword wide
      $x7 = "Conhost --headless cmd.exe /c taskkill /IM discord.exe /F" fullword wide
      $x8 = "Conhost --headless cmd.exe /c start firefox --profile=\"" fullword wide
      $x9 = "costura.gma.system.mousekeyhook.dll.compressed|5.7.1.0|Gma.System.MouseKeyHook, Version=5.7.1.0, Culture=neutral, PublicKeyToken" ascii
      $x10 = "costura.gma.system.mousekeyhook.dll.compressed|5.7.1.0|Gma.System.MouseKeyHook, Version=5.7.1.0, Culture=neutral, PublicKeyToken" ascii
      $x11 = "costura.sharpdx.d3dcompiler.dll.compressed|4.2.0.0|SharpDX.D3DCompiler, Version=4.2.0.0, Culture=neutral, PublicKeyToken=b4dcf0f" ascii
      $x12 = "costura.sharpdx.dxgi.dll.compressed|4.2.0.0|SharpDX.DXGI, Version=4.2.0.0, Culture=neutral, PublicKeyToken=b4dcf0f35e5521f1|Shar" ascii
      $x13 = "costura.sharpdx.dll.compressed|4.2.0.0|SharpDX, Version=4.2.0.0, Culture=neutral, PublicKeyToken=b4dcf0f35e5521f1|SharpDX.dll|09" ascii
      $x14 = "costura.naudio.wasapi.dll.compressed|2.2.1.0|NAudio.Wasapi, Version=2.2.1.0, Culture=neutral, PublicKeyToken=e279aa5131008a41|NA" ascii
      $x15 = "costura.aforge.video.directshow.dll.compressed|2.2.5.0|AForge.Video.DirectShow, Version=2.2.5.0, Culture=neutral, PublicKeyToken" ascii
      $x16 = "costura.naudio.core.dll.compressed|2.2.1.0|NAudio.Core, Version=2.2.1.0, Culture=neutral, PublicKeyToken=e279aa5131008a41|NAudio" ascii
      $x17 = "costura.protobuf-net.dll.compressed|2.4.0.0|protobuf-net, Version=2.4.0.0, Culture=neutral, PublicKeyToken=257b51d87d2e4d67|prot" ascii
      $x18 = "costura.sharpdx.mathematics.dll.compressed|4.2.0.0|SharpDX.Mathematics, Version=4.2.0.0, Culture=neutral, PublicKeyToken=b4dcf0f" ascii
      $x19 = "costura.naudio.winforms.dll.compressed|2.2.1.0|NAudio.WinForms, Version=2.2.1.0, Culture=neutral, PublicKeyToken=e279aa5131008a4" ascii
      $x20 = "costura.aforge.dll.compressed|2.2.5.0|AForge, Version=2.2.5.0, Culture=neutral, PublicKeyToken=c1db6ff4eaa06aeb|AForge.dll|2DA9E" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) )
      ) or ( all of them )
}

rule MAL_BETRAY_RAT_AUG25_2fa_6_1_25_1 {
   meta:
      description = "MAL_BETRAY_RAT_AUG25 - from files 2fa.exe, 6-1-25.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "56af25d62871b59803c9b9a31dd8e74796d43733da684f8ee2925dfba0360f7b"
      hash2 = "cb8cdc3ba28a9a8d76bd477aa4f0b7e4ef6b97c66a58524db4f717f53ec09891"
   strings:
      $s1 = "3f1bFRp0bPxzSvG5ogbgQfqEnEWgztBchW4WLhpz8zzPdjsjsZMkodVlOERt8FwawlNtWsTcgqs/ZLLiIE9UVAvoGNcfV0B7FPlI+9hX1Elxz6ZfW78PXinYa2SK8+PU" wide
      $s2 = "VvVmxF0z11DK949+YzEv3Fh7ANYnGK76NEQvZ8yWoW0lshjy4mKCq8yBwiqJeXGfov3srWBh8GBg93P9LNfFfPQHsiVq6HezeVgvjWo6vTVy1niBWCD4D4XvIzIga0ki" wide
      $s3 = "IEp5HokLv4SpY3b6" fullword ascii
      $s4 = "YJUzmftPtXbBlkLmtLU" fullword ascii
      $s5 = "wt2CP9dH663gq1u7vFTPjs1cGR" fullword ascii
      $s6 = "SXfrIfeeFNkFdLlOH3pJ09IzaL" fullword ascii
      $s7 = "cU2PsPYDgIBOJRJubovihSn" fullword ascii
      $s8 = "sM6oSsIJbTlOwsiSKu9FXrJsPY" fullword ascii
      $s9 = "3brdDYdO18Wzd1sPY" fullword ascii
      $s10 = "x7M1mvXR9xyGXTmB0OpGDiRcnK" fullword ascii
      $s11 = "7aSSi901QCZ4mzDyMl4x29TlogA" fullword ascii
      $s12 = "cKmsIEWAehCB4yu7b0kSY" fullword ascii
      $s13 = "snuhqsellspr" fullword ascii
      $s14 = "hshpspujrxiyshyzjyyqzjdzbo" fullword ascii
      $s15 = "esipmgrliufxjvsygqmbhpimxotnl" fullword ascii
      $s16 = "kswssenwsozyu" fullword ascii
      $s17 = "zhelhnhivtskbwzsoulfpccndadn" fullword ascii
      $s18 = "foorhiludin" fullword ascii
      $s19 = "xznlvpntmgxrhkokxobscwg" fullword ascii
      $s20 = "ewcspplnivusyxyevykvmflvf" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_RAT_AUG25_2fa_road_water_2faBeta_uac_6_1_25_2 {
   meta:
      description = "MAL_BETRAY_RAT_AUG25 - from files 2fa.exe, road.exe, water.exe, 2faBeta.exe, uac.exe, 6-1-25.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "56af25d62871b59803c9b9a31dd8e74796d43733da684f8ee2925dfba0360f7b"
      hash2 = "c8f6f00b8ee92ee530bef1d760e378e85123dc69a146ee247eac2ea4d760a15a"
      hash3 = "798494934d245a7b4d6f542fa8dcb89a705e0c87237f2d3e5520a9b3266d9987"
      hash4 = "5acae9ee314434f35112164ced87d71032d05bd97716719fa0338aee5c6ed67e"
      hash5 = "f2c960225df390a81642300de838bd1c392bdf0e273dd7d4a757ea783c972f13"
      hash6 = "cb8cdc3ba28a9a8d76bd477aa4f0b7e4ef6b97c66a58524db4f717f53ec09891"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s2 = "costura.sharpdx.dxgi.dll.compressed" fullword wide
      $s3 = "costura.sharpdx.dll.compressed" fullword wide
      $s4 = "costura.aforge.video.dll.compressed" fullword wide
      $s5 = "costura.sharpdx.direct3d11.dll.compressed" fullword wide
      $s6 = "costura.aforge.video.directshow.dll.compressed" fullword wide
      $s7 = "<GetPasswords>b__0" fullword ascii
      $s8 = "GetPasswords" fullword ascii
      $s9 = "encryptedPassword" fullword wide
      $s10 = "set_Processes" fullword ascii
      $s11 = "timePasswordChanged" fullword ascii
      $s12 = "encryptedUsername" fullword wide
      $s13 = "password_value" fullword wide
      $s14 = "moz_logins" fullword wide
      $s15 = "OpenReadonlySubKeySafe" fullword ascii
      $s16 = "ResultDescriptor" fullword ascii
      $s17 = "Texture2DDescription" fullword ascii
      $s18 = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide
      $s19 = "https://api.ipify.org/" fullword wide
      $s20 = "get_MonikerString" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_RAT_AUG25_2fa_road_uac_6_1_25_3 {
   meta:
      description = "MAL_BETRAY_RAT_AUG25 - from files 2fa.exe, road.exe, uac.exe, 6-1-25.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "56af25d62871b59803c9b9a31dd8e74796d43733da684f8ee2925dfba0360f7b"
      hash2 = "c8f6f00b8ee92ee530bef1d760e378e85123dc69a146ee247eac2ea4d760a15a"
      hash3 = "f2c960225df390a81642300de838bd1c392bdf0e273dd7d4a757ea783c972f13"
      hash4 = "cb8cdc3ba28a9a8d76bd477aa4f0b7e4ef6b97c66a58524db4f717f53ec09891"
   strings:
      $x1 = "Conhost --headless cmd.exe /c start opera.exe --user-data-dir=\"" fullword wide
      $x2 = "Conhost --headless cmd.exe /c start operagx.exe --user-data-dir=\"" fullword wide
      $x3 = "Conhost --headless cmd.exe /c start msedge.exe --start-maximized --no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable" wide
      $x4 = "costura.pulsar.common.dll.compressed|1.6.2.0|Pulsar.Common, Version=1.6.2.0, Culture=neutral, PublicKeyToken=null|Pulsar.Common." ascii
      $x5 = "> ERROR: chrome.dll not found in process modules after injection" fullword wide
      $x6 = "costura.pulsar.common.dll.compressed|1.6.2.0|Pulsar.Common, Version=1.6.2.0, Culture=neutral, PublicKeyToken=null|Pulsar.Common." ascii
      $s7 = "uacbypass.bat" fullword wide
      $s8 = "> Searching for chrome.dll in process modules:" fullword wide
      $s9 = "\\chrome.dll" fullword wide
      $s10 = "> Found chrome.dll at address: {0:X}" fullword wide
      $s11 = "> Got address of chrome.dll: {0:X}" fullword wide
      $s12 = "<meta http-equiv='Content-Type' content='text/html; charset=utf-8' />Log created on " fullword wide
      $s13 = "<FindLatestChromeVersion>b__26_0" fullword ascii
      $s14 = "> ERROR: Failed to convert file offset to RVA" fullword wide
      $s15 = "> ERROR in ApplyPatch: " fullword wide
      $s16 = "1.6.2.0" fullword wide
      $s17 = "Z%o%ni" fullword ascii
      $s18 = "%- &(|" fullword ascii
      $s19 = " + {0}" fullword wide
      $s20 = "<StartAnti>b__3_0" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_RAT_AUG25_RobloxDowngrader_RCE_4 {
   meta:
      description = "MAL_BETRAY_RAT_AUG25 - from files RobloxDowngrader.exe, RCE.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "a5df226a516fdd4e00e8b49416f21700f307d22aa0aec5cbda1134a66a935d9e"
      hash2 = "4d10bf73250cd0b9843cdde72751b93e904fa6c936f4e5caa5e5527f7571254b"
   strings:
      $s1 = " Type Descriptor'" fullword ascii
      $s2 = "operator<=>" fullword ascii
      $s3 = "operator co_await" fullword ascii
      $s4 = " Class Hierarchy Descriptor'" fullword ascii
      $s5 = " Base Class Descriptor at (" fullword ascii
      $s6 = " Complete Object Locator'" fullword ascii
      $s7 = " delete[]" fullword ascii
      $s8 = "__swift_3" fullword ascii
      $s9 = "__swift_2" fullword ascii
      $s10 = "__swift_1" fullword ascii
      $s11 = " delete" fullword ascii
      $s12 = " A_A^_" fullword ascii
      $s13 = "H;xXu5" fullword ascii
      $s14 = " A_A^A]A\\_" fullword ascii
      $s15 = "u4I9}(" fullword ascii
      $s16 = " new[]" fullword ascii
      $s17 = " A_A^A]A\\_^]" fullword ascii
      $s18 = "api-ms-" fullword wide
      $s19 = " Base Class Array'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_RAT_AUG25_2fa_road_water_2faBeta_uac_BootstrapperNew_6_1_25_5 {
   meta:
      description = "MAL_BETRAY_RAT_AUG25 - from files 2fa.exe, road.exe, water.exe, 2faBeta.exe, uac.exe, BootstrapperNew.exe, 6-1-25.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "56af25d62871b59803c9b9a31dd8e74796d43733da684f8ee2925dfba0360f7b"
      hash2 = "c8f6f00b8ee92ee530bef1d760e378e85123dc69a146ee247eac2ea4d760a15a"
      hash3 = "798494934d245a7b4d6f542fa8dcb89a705e0c87237f2d3e5520a9b3266d9987"
      hash4 = "5acae9ee314434f35112164ced87d71032d05bd97716719fa0338aee5c6ed67e"
      hash5 = "f2c960225df390a81642300de838bd1c392bdf0e273dd7d4a757ea783c972f13"
      hash6 = "5bcc68604c4c4add6d592e0455156024e52ff10f9f06daa1f543b005d7c2a53f"
      hash7 = "cb8cdc3ba28a9a8d76bd477aa4f0b7e4ef6b97c66a58524db4f717f53ec09891"
   strings:
      $s1 = "      <!-- Windows 7 -->" fullword ascii
      $s2 = "      <!-- Windows Vista -->" fullword ascii
      $s3 = "      <!-- Windows 8.1 -->" fullword ascii
      $s4 = "      <!-- Windows 10 -->" fullword ascii
      $s5 = "      <!-- Windows 8 -->" fullword ascii
      $s6 = ".compressed" fullword wide
      $s7 = "ReadFromEmbeddedResources" fullword ascii
      $s8 = "FodyVersion" fullword ascii
      $s9 = "Costura" fullword ascii
      $s10 = "symbolNames" fullword ascii
      $s11 = "CultureToString" fullword ascii
      $s12 = "ReadExistingAssembly" fullword ascii
      $s13 = "<>8__1" fullword ascii
      $s14 = "requestedAssemblyName" fullword ascii
      $s15 = "nullCache" fullword ascii
      $s16 = "nullCacheLock" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_RAT_AUG25_water_BootstrapperNew_6 {
   meta:
      description = "MAL_BETRAY_RAT_AUG25 - from files water.exe, BootstrapperNew.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "798494934d245a7b4d6f542fa8dcb89a705e0c87237f2d3e5520a9b3266d9987"
      hash2 = "5bcc68604c4c4add6d592e0455156024e52ff10f9f06daa1f543b005d7c2a53f"
   strings:
      $s1 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii
      $s2 = "costura.costura.dll.compressed" fullword wide
      $s3 = "ProcessExtensions" fullword ascii
      $s4 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii
      $s5 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii
      $s6 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii
      $s7 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii
      $s8 = "             requestedExecutionLevel node with one of the following." fullword ascii
      $s9 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii
      $s10 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii
      $s11 = ".NET Framework 4.8" fullword ascii
      $s12 = ".NETFramework,Version=v4.8" fullword ascii
      $s13 = "          processorArchitecture=\"*\"" fullword ascii
      $s14 = "          publicKeyToken=\"6595b64144ccf1df\"" fullword ascii
      $s15 = "costura" fullword wide
      $s16 = "          version=\"6.0.0.0\"" fullword ascii
      $s17 = "          name=\"Microsoft.Windows.Common-Controls\"" fullword ascii
      $s18 = "        -->" fullword ascii
      $s19 = "             If you want to change the Windows User Account Control level replace the " fullword ascii
      $s20 = "<FolderPath>k__BackingField" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20000KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_RAT_AUG25_2fa_road_water_2faBeta_uac_BootstrapperNew_6_1_25_RCE_7 {
   meta:
      description = "MAL_BETRAY_RAT_AUG25 - from files 2fa.exe, road.exe, water.exe, 2faBeta.exe, uac.exe, BootstrapperNew.exe, 6-1-25.exe, RCE.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "56af25d62871b59803c9b9a31dd8e74796d43733da684f8ee2925dfba0360f7b"
      hash2 = "c8f6f00b8ee92ee530bef1d760e378e85123dc69a146ee247eac2ea4d760a15a"
      hash3 = "798494934d245a7b4d6f542fa8dcb89a705e0c87237f2d3e5520a9b3266d9987"
      hash4 = "5acae9ee314434f35112164ced87d71032d05bd97716719fa0338aee5c6ed67e"
      hash5 = "f2c960225df390a81642300de838bd1c392bdf0e273dd7d4a757ea783c972f13"
      hash6 = "5bcc68604c4c4add6d592e0455156024e52ff10f9f06daa1f543b005d7c2a53f"
      hash7 = "cb8cdc3ba28a9a8d76bd477aa4f0b7e4ef6b97c66a58524db4f717f53ec09891"
      hash8 = "4d10bf73250cd0b9843cdde72751b93e904fa6c936f4e5caa5e5527f7571254b"
   strings:
      $s1 = "  </compatibility>" fullword ascii
      $s2 = "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" fullword ascii
      $s3 = "008deee3d3f0" ascii
      $s4 = "  <application xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s5 = "d69d4a4a6e38" ascii
      $s6 = "a2440225f93a" ascii
      $s7 = "48fd50a15a9a" ascii
      $s8 = "83d0f6d0da78" ascii
      $s9 = "  </application>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_RAT_AUG25_2fa_road_2faBeta_uac_6_1_25_RCE_8 {
   meta:
      description = "MAL_BETRAY_RAT_AUG25 - from files 2fa.exe, road.exe, 2faBeta.exe, uac.exe, 6-1-25.exe, RCE.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "56af25d62871b59803c9b9a31dd8e74796d43733da684f8ee2925dfba0360f7b"
      hash2 = "c8f6f00b8ee92ee530bef1d760e378e85123dc69a146ee247eac2ea4d760a15a"
      hash3 = "5acae9ee314434f35112164ced87d71032d05bd97716719fa0338aee5c6ed67e"
      hash4 = "f2c960225df390a81642300de838bd1c392bdf0e273dd7d4a757ea783c972f13"
      hash5 = "cb8cdc3ba28a9a8d76bd477aa4f0b7e4ef6b97c66a58524db4f717f53ec09891"
      hash6 = "4d10bf73250cd0b9843cdde72751b93e904fa6c936f4e5caa5e5527f7571254b"
   strings:
      $s1 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" fullword ascii
      $s2 = "      <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" fullword ascii
      $s3 = "      <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" fullword ascii
      $s4 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" fullword ascii
      $s5 = "      <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 23000KB and ( all of them )
      ) or ( all of them )
}

