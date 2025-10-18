/*
   YARA Rule Set
   Author: DeTraced Security
   Date: 2025-10-17
   Identifier: MAL_BETRAY_XWORM_AUG25
   Reference: https://detraced.org/posts/infostealer-turned-ransomware
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule MAL_BETRAY_XWORM_AUG25_FastColoredTextBox {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - file FastColoredTextBox.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "6eb6a0c64ee8c575f56a93065138b17883118cf231a6916fc601ec86793d85bf"
   strings:
      $x1 = "(@@CONNECTIONS|@@CPU_BUSY|@@CURSOR_ROWS|@@DATEFIRST|@@DATEFIRST|@@DBTS|@@ERROR|@@FETCH_STATUS|@@IDENTITY|@@IDLE|@@IO_BUSY|@@LANG" wide
      $x2 = "\\b(ADD|ALL|AND|ANY|AS|ASC|AUTHORIZATION|BACKUP|BEGIN|BETWEEN|BREAK|BROWSE|BY|CASCADE|CHECK|CHECKPOINT|CLOSE|CLUSTERED|COLLATE|C" wide
      $x3 = "System.ComponentModel.Design.MultilineStringEditor, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d5" ascii
      $x4 = "System.ComponentModel.Design.MultilineStringEditor, System.Design, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d5" ascii
      $x5 = "\\b(AddHandler|AddressOf|Alias|And|AndAlso|As|Boolean|ByRef|Byte|ByVal|Call|Case|Catch|CBool|CByte|CChar|CDate|CDbl|CDec|Char|CI" wide
      $s6 = "Tab=IndentIncrease, Escape=ClearHints, PgUp=GoPageUp, PgDn=GoPageDown, End=GoEnd, Home=GoHome, Left=GoLeft, Up=GoUp, Right=GoRig" ascii
      $s7 = "H:\\BACKUP 2024 - JULY 11\\Telegram Desktop\\XWorm V5.6 Optimized Lifetime\\XWorm V5.6 Optimized Lifetime\\XWorm V5.6 Optimized " ascii
      $s8 = "stem.Drawing.Design.UITypeEditor, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
      $s9 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s10 = "0a3auSystem.Drawing.Design.UITypeEditor, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
      $s11 = "ZSystem.UInt32, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s12 = "ExecuteInsertTextCommand" fullword ascii
      $s13 = "\\b(abstract|as|base|bool|break|byte|case|catch|char|checked|class|const|continue|decimal|default|delegate|do|double|else|enum|e" wide
      $s14 = "\\b(ALTER APPLICATION ROLE|ALTER ASSEMBLY|ALTER ASYMMETRIC KEY|ALTER AUTHORIZATION|ALTER BROKER PRIORITY|ALTER CERTIFICATE|ALTER" wide
      $s15 = "|System.Windows.Forms.Design.FileNameEditor, System.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3auSy" ascii
      $s16 = "\"FastColoredTextBoxNS.HotkeysEditoruSystem.Drawing.Design.UITypeEditor, System.Drawing, Version=4.0.0.0, Culture=neutral, Publi" ascii
      $s17 = "GetOperationSystemPlatform" fullword ascii
      $s18 = "All, Ctrl+B=BookmarkLine, Ctrl+C=Copy, Ctrl+E=MacroExecute, Ctrl+F=FindDialog, Ctrl+G=GoToDialog, Ctrl+H=ReplaceDialog, Ctrl+I=A" ascii
      $s19 = "FastColoredTextBox.dll" fullword wide
      $s20 = "\"FastColoredTextBoxNS.HotkeysEditoruSystem.Drawing.Design.UITypeEditor, System.Drawing, Version=4.0.0.0, Culture=neutral, Publi" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule MAL_BETRAY_XWORM_AUG25_XWorm {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - file XWorm.pdb"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "ba86707deab2ecf159f7b14e03e7ce94662f9ab5a074d8918bd40c3ccb290216"
   strings:
      $s1 = "keylogger" fullword ascii
      $s2 = "PSystem.Numerics.dll" fullword ascii
      $s3 = "FastColoredTextBox.dll" fullword ascii
      $s4 = "GMap.NET.WindowsForms.dll" fullword ascii
      $s5 = "IconExtractor.dll" fullword ascii
      $s6 = "GMap.NET.Core.dll" fullword ascii
      $s7 = "d~System.Xml.Linq.dll" fullword ascii
      $s8 = "[NdSystem.Core.dll" fullword ascii
      $s9 = "Guna.UI2.dll" fullword ascii
      $s10 = "XWorm.Keylogger.Designer.cs" fullword ascii
      $s11 = "System.Windows.Forms&Microsoft.VisualBasic.CompilerServices" fullword ascii
      $s12 = "W@mscorlib.dll" fullword ascii
      $s13 = "XWorm.ProcessV.Designer.cs" fullword ascii
      $s14 = "keylogger2" fullword ascii
      $s15 = "System.ComponentModel.Design/" fullword ascii
      $s16 = "Keylogger.cs" fullword ascii
      $s17 = "processV2" fullword ascii
      $s18 = "System.DrawingSystem.Runtime.CompilerServices" fullword ascii
      $s19 = "\"c7SimpleObfuscator.dll" fullword ascii
      $s20 = "processV" fullword ascii
   condition:
      uint16(0) == 0x5342 and filesize < 600KB and
      8 of them
}

rule MAL_BETRAY_XWORM_AUG25_IconExtractor {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - file IconExtractor.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "440912d85d2f98bb4f508ab82847067c18e1e15be0d8ecdcff0cc19327527fc2"
   strings:
      $x1 = "C:\\Users\\HMJ\\Desktop\\IconExtractor-master\\IconExtractor\\obj\\Release\\IconExtractor.pdb" fullword ascii
      $s2 = "IconExtractor.dll" fullword wide
      $s3 = "ICONRESHEAD" fullword ascii
      $s4 = "ICONFILEHEAD" fullword ascii
      $s5 = "GetIconResInfo" fullword ascii
      $s6 = "get_iconBytes" fullword ascii
      $s7 = "<GetIconResInfo>b__0" fullword ascii
      $s8 = "DONT_RESOLVE_DLL_REFERENCES" fullword ascii
      $s9 = "get_iconFileInf" fullword ascii
      $s10 = "GetResourceBytes" fullword ascii
      $s11 = "Toolbelt.Drawing" fullword ascii
      $s12 = "Toolbelt.Drawing.Win32" fullword ascii
      $s13 = "IGNORE_CODE_AUTHZ_LEVEL" fullword ascii
      $s14 = "ICONRESINF" fullword ascii
      $s15 = "ICONFILEINF" fullword ascii
      $s16 = "<iconFileInf>i__Field" fullword ascii
      $s17 = "<iconFileInf>j__TPar" fullword ascii
      $s18 = "<WriteIconData>b__0" fullword ascii
      $s19 = "lpszType" fullword ascii
      $s20 = "<iconBytes>i__Field" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule MAL_BETRAY_XWORM_AUG25_Fixer {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - file Fixer.bat"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "a11703fd47d16020fa099a95bb4e46247d32cf8821dc1826e77a971cdd3c4c55"
   strings:
      $s1 = "echo If XWorm Does Not work - Run This Script As Administrator!" fullword ascii
      $s2 = "title XWorm - Fixer" fullword ascii
      $s3 = "lodctr /r" fullword ascii
   condition:
      uint16(0) == 0x6540 and filesize < 1KB and
      all of them
}

rule MAL_BETRAY_XWORM_AUG25_XWorm_exe {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - file XWorm.exe.config"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "60fda282bbc1aeb836b158dd6dde523e5225b365cc6fc0338dab9e82347b1e2d"
   strings:
      $s1 = "    <supportedRuntime version=\"v4.0\" sku=\".NETFramework,Version=v4.5\" />" fullword ascii
      $s2 = "  <startup>" fullword ascii
      $s3 = "  </startup>" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule MAL_BETRAY_XWORM_AUG25_VoiceChat_NAudio_WSound_Microphone_0 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files VoiceChat.dll, NAudio.dll, WSound.dll, Microphone.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "1a2da0a66c7771962d525b8fe9491052efbd5f87b97d935c267fd96519b5a35e"
      hash2 = "81b3f1dc3f1eac9762b8a292751a44b64b87d0d4c3982debfdd2621012186451"
      hash3 = "4bea01b7d691d1f59ca0bb5149e5baf71cde71019da3d352141b1d4921e70bc2"
      hash4 = "612898afdf9120cfef5843f9b136c66ecc3e0bb6f3d1527d0599a11988b7783c"
   strings:
      $x1 = "jSystem.CodeDom.MemberAttributes, System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size," ascii
      $s2 = " System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3amSystem.Globalization.CultureInfo, mscorlib, V" ascii
      $s3 = "get_GetProcessID" fullword ascii
      $s4 = "MF_E_SINK_NO_SAMPLES_PROCESSED" fullword ascii
      $s5 = "ersion=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089PADPADP" fullword ascii
      $s6 = "Not an AIFF file - no AIFF/AIFC header." fullword wide
      $s7 = "MF_E_NON_PE_PROCESS" fullword ascii
      $s8 = "DmoInPlaceProcessReturn" fullword ascii
      $s9 = "_MFT_PROCESS_OUTPUT_FLAGS" fullword ascii
      $s10 = "MF_E_PROCESS_RESTART_REQUIRED" fullword ascii
      $s11 = "get_IsSystemSoundsSession" fullword ascii
      $s12 = "MFT_PROCESS_OUTPUT_STATUS_NEW_STREAMS" fullword ascii
      $s13 = "System.Collections.Generic.IEnumerator<NAudio.MediaFoundation.IMFActivate>.get_Current" fullword ascii
      $s14 = "MF_E_ALL_PROCESS_RESTART_REQUIRED" fullword ascii
      $s15 = "_MFT_PROCESS_OUTPUT_STATUS" fullword ascii
      $s16 = "qwNumSamplesProcessed" fullword ascii
      $s17 = "qwByteCountProcessed" fullword ascii
      $s18 = "llLastTimestampProcessed" fullword ascii
      $s19 = "MFT_INPUT_STREAM_PROCESSES_IN_PLACE" fullword ascii
      $s20 = "DmoInPlaceProcessFlags" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_Recovery_Newtonsoft_Json_Stealer_1 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files Recovery.dll, Newtonsoft.Json.dll, Stealer.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "66dbe3b90371fe58caa957e83c1c1f0acce941a36cf140a0f07e64403dd13303"
      hash2 = "e1e27af7b07eeedf5ce71a9255f0422816a6fc5849a483c6714e1b472044fa9d"
      hash3 = "018e06f57725563e4525700edffafb1b062bf5d4b0e9fee498507f0f8200fcdf"
   strings:
      $s1 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,Newtonsoft.Json.Linq.JToken>>.get_I" ascii
      $s2 = "System.Collections.Generic.IEnumerator<System.Collections.Generic.KeyValuePair<System.String,Newtonsoft.Json.Linq.JToken>>.get_C" ascii
      $s3 = "get_ProcessExtensionDataNames" fullword ascii
      $s4 = "get_ProcessDictionaryKeys" fullword ascii
      $s5 = "System.Runtime.CompilerServices.IsByRefLikeAttribute" fullword wide
      $s6 = "BSON reading and writing has been moved to its own package. See https://www.nuget.org/packages/Newtonsoft.Json.Bson for more det" ascii
      $s7 = "System.Collections.Generic.IEnumerator<System.Collections.Generic.KeyValuePair<System.Object,System.Object>>.get_Current" fullword ascii
      $s8 = "<ExecuteFilter>b__2_0" fullword ascii
      $s9 = "BSON reading and writing has been moved to its own package. See https://www.nuget.org/packages/Newtonsoft.Json.Bson for more det" ascii
      $s10 = "uJSON Schema validation has been moved to its own package. See https://www.newtonsoft.com/jsonschema for more details." fullword ascii
      $s11 = "System.ComponentModel.ComponentConverter" fullword wide
      $s12 = "System.ComponentModel.ReferenceConverter" fullword wide
      $s13 = "System.Collections.Generic.IEnumerator<System.Collections.Generic.KeyValuePair<System.String,Newtonsoft.Json.Linq.JToken>>.Curre" ascii
      $s14 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,Newtonsoft.Json.Linq.JToken>>.IsRea" ascii
      $s15 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,Newtonsoft.Json.Linq.JToken>>.Conta" ascii
      $s16 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,Newtonsoft.Json.Linq.JToken>>.Remov" ascii
      $s17 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,Newtonsoft.Json.Linq.JToken>>.CopyT" ascii
      $s18 = "<ProcessDictionaryKeys>k__BackingField" fullword ascii
      $s19 = "set_ProcessExtensionDataNames" fullword ascii
      $s20 = "processExtensionDataNames" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_Stealer_FilesSearcher_2 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files Stealer.dll, FilesSearcher.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "018e06f57725563e4525700edffafb1b062bf5d4b0e9fee498507f0f8200fcdf"
      hash2 = "e66e1273dc59ee9e05ce3e02f1b760b18dd296a47d92b3ce5b24efb48e5fb21b"
   strings:
      $s1 = "<ProcessExtraFieldUnixTimes>b__0" fullword ascii
      $s2 = "GetUnsupportedCompressionMethod" fullword ascii
      $s3 = "GetUnsupportedAlgorithm" fullword ascii
      $s4 = "Failed to find decompressor matching {0}" fullword wide
      $s5 = "get_RetrievalEntries" fullword ascii
      $s6 = "compressionMethodName" fullword ascii
      $s7 = "unsupportedAlgorithmId" fullword ascii
      $s8 = "get_IgnoreDuplicateFiles" fullword ascii
      $s9 = "archiveStream" fullword ascii
      $s10 = "InnerClose" fullword ascii
      $s11 = "_entriesInsensitive" fullword ascii
      $s12 = "RetrievalEntries" fullword ascii
      $s13 = "\\(([^'\\f\\n\\r\\t\\v\\x85\\p{Z}])" fullword wide
      $s14 = "\\)([^'\\f\\n\\r\\t\\v\\x85\\p{Z}])" fullword wide
      $s15 = "input2" fullword wide
      $s16 = " 3333_" fullword ascii
      $s17 = "calculatedCrc32" fullword ascii
      $s18 = " UUUU_" fullword ascii
      $s19 = " PK00;" fullword ascii
      $s20 = "set_IgnoreDuplicateFiles" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_VoiceChat_WSound_Microphone_3 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files VoiceChat.dll, WSound.dll, Microphone.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "1a2da0a66c7771962d525b8fe9491052efbd5f87b97d935c267fd96519b5a35e"
      hash2 = "4bea01b7d691d1f59ca0bb5149e5baf71cde71019da3d352141b1d4921e70bc2"
      hash3 = "612898afdf9120cfef5843f9b136c66ecc3e0bb6f3d1527d0599a11988b7783c"
   strings:
      $s1 = "GetSessionIdentifier" fullword ascii
      $s2 = "GetSessionInstanceIdentifier" fullword ascii
      $s3 = "IsSystemSoundsSession" fullword ascii
      $s4 = "SweepLengthSecs" fullword ascii
      $s5 = "FrequencyEndLog" fullword ascii
      $s6 = "PostEqBandWidth" fullword ascii
      $s7 = "PostEqCenterFrequency" fullword ascii
      $s8 = "FrequencyLog" fullword ascii
      $s9 = "filterpos" fullword ascii
      $s10 = "filtercnt" fullword ascii
      $s11 = "fracpos" fullword ascii
      $s12 = "filterq" fullword ascii
      $s13 = "AsioDriver" fullword ascii
      $s14 = "UniqueMaterialIdentifier" fullword ascii
      $s15 = "MediaFoundationReader" fullword ascii
      $s16 = "AudioSessionManager" fullword ascii
      $s17 = "SingleReaderObject" fullword ascii
      $s18 = "AudioSessionControl" fullword ascii
      $s19 = "IAudioSessionManager" fullword ascii
      $s20 = "CreateSourceReaderFromByteStream" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_Recovery_Stealer_4 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files Recovery.dll, Stealer.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "66dbe3b90371fe58caa957e83c1c1f0acce941a36cf140a0f07e64403dd13303"
      hash2 = "018e06f57725563e4525700edffafb1b062bf5d4b0e9fee498507f0f8200fcdf"
   strings:
      $s1 = "ProcessDictionaryKeys" fullword ascii
      $s2 = "ProcessExtensionDataNames" fullword ascii
      $s3 = "PreComputeUnionReader" fullword ascii
      $s4 = "Newtonsoft.Json.<PrivateImplementationDetails>" fullword ascii
      $s5 = "PreComputeUnionTagReader" fullword ascii
      $s6 = "<GetEnumerator>d__61" fullword ascii
      $s7 = "<GetEnumerator>b__27_0" fullword ascii
      $s8 = "OverrideSpecifiedNames" fullword ascii
      $s9 = "CommentHandling" fullword ascii
      $s10 = "AutoCompleteOnClose" fullword ascii
      $s11 = "ErrorWhenNoMatch" fullword ascii
      $s12 = "DictionaryKeyResolver" fullword ascii
      $s13 = "PropertyNameComparison" fullword ascii
      $s14 = "PreComputeUnionConstructor" fullword ascii
      $s15 = "TagReader" fullword ascii
      $s16 = "serializationBinder" fullword ascii
      $s17 = "Discord" fullword ascii
      $s18 = "Telegram" fullword ascii
      $s19 = "Stealer" fullword ascii
      $s20 = "GetUnionCaseInfoTag" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_WebCam_HRDP_5 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files WebCam.dll, HRDP.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "8d413b40aef41e53557d91f3b3ac64cfc13adb0f8c3edc364e7b8501170e2657"
      hash2 = "4aa18745a5fddf7ec14adaff3ad1b4df1b910f4b6710bf55eb27fb3942bb67de"
   strings:
      $s1 = " Type Descriptor'" fullword ascii
      $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s3 = " Class Hierarchy Descriptor'" fullword ascii
      $s4 = " Base Class Descriptor at (" fullword ascii
      $s5 = " Complete Object Locator'" fullword ascii
      $s6 = " delete[]" fullword ascii
      $s7 = " delete" fullword ascii
      $s8 = "      <requestedPrivileges>" fullword ascii
      $s9 = " H3E H3E" fullword ascii
      $s10 = " A_A^A\\" fullword ascii
      $s11 = " A_A^A\\_^" fullword ascii
      $s12 = " new[]" fullword ascii
      $s13 = " A_A^A]A\\_" fullword ascii
      $s14 = " Base Class Array'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_GMap_NET_Core_GMap_NET_WindowsForms_6 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files GMap.NET.Core.dll, GMap.NET.WindowsForms.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "58c755fcfc65cddea561023d736e8991f0ad69da5e1378dea59e98c5db901b86"
      hash2 = "741e1a8f05863856a25d101bd35bf97cba0b637f0c04ecb432c1d85a78ef1365"
   strings:
      $s1 = "GMap.NET.WindowsForms.dll" fullword wide
      $s2 = "ShowExportDialog" fullword ascii
      $s3 = "ShowImportDialog" fullword ascii
      $s4 = "get_IsRunningOnMono" fullword ascii
      $s5 = "GMap.NET.Internals" fullword ascii
      $s6 = "GMap.NET.Core" fullword ascii
      $s7 = "GMap.NET.Projections" fullword ascii
      $s8 = "GMap.NET" fullword wide
      $s9 = "GMap.NET.WindowsForms" fullword wide
      $s10 = "get_MapProvider" fullword ascii
      $s11 = "get_HeightLat" fullword ascii
      $s12 = "get_WidthLng" fullword ascii
      $s13 = "get_ViewArea" fullword ascii
      $s14 = "get_Overlays" fullword ascii
      $s15 = "GetMaxZoomToFitRect" fullword ascii
      $s16 = "GetAreaTileList" fullword ascii
      $s17 = "GetGroundResolution" fullword ascii
      $s18 = "GetTileWithNoLock" fullword ascii
      $s19 = "get_PositionPixel" fullword ascii
      $s20 = "GetTileMatrixMaxXY" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_Ngrok_Installer_Stealer_7 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files Ngrok-Installer.dll, Stealer.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "b574aabf02a65aa3b6f7bfff0a574873ce96429d3f708a10f87bc1f6518f14aa"
      hash2 = "018e06f57725563e4525700edffafb1b062bf5d4b0e9fee498507f0f8200fcdf"
   strings:
      $s1 = "unknown compression method" fullword wide
      $s2 = "noheader" fullword ascii
      $s3 = "get_IsTagged" fullword ascii
      $s4 = "config_table" fullword ascii
      $s5 = "CompressionAlgorithm" fullword ascii
      $s6 = "InfBlocks" fullword ascii
      $s7 = "SaveDir" fullword ascii
      $s8 = "inflate_flush" fullword ascii
      $s9 = "ZInputStream" fullword ascii
      $s10 = "ZOutputStream" fullword ascii
      $s11 = "bsStream" fullword ascii
      $s12 = "CBZip2InputStream" fullword ascii
      $s13 = "inflate_mask" fullword ascii
      $s14 = "IsTagged" fullword ascii
      $s15 = "next_in_index" fullword ascii
      $s16 = "set_dictionary" fullword ascii
      $s17 = "sync_point" fullword ascii
      $s18 = "next_out_index" fullword ascii
      $s19 = "DIST_CODE_LEN" fullword ascii
      $s20 = "CBZip2OutputStream" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_noanti_Wiz_XClient_1_XClient_2_installer_8 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files noanti.exe, Wiz.exe, XClient.exe, 1.exe, XClient-2.exe, installer.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "cbfd0dba27e9818a322ac849f0f6321675e97ac82a63ed3805cd3a5b84b3948f"
      hash2 = "4282a3625eeb9d921474ed4f35b3632ccb69e5f951166b9200ac6ee2d42ea493"
      hash3 = "4a1f05acef115eaeffcf2382a9816f6d86a160515ba2d3949eb5215e03f87209"
      hash4 = "b708f2ed06dee2fb99250a733323b939bcaad7da59b0d21a5cf314f3cc926452"
      hash5 = "dd8f5088a7d6c1e18a5a4d3a64a309dd981280adcbc0b4ec343019a5d540b518"
      hash6 = "ad02d29c876bb868e3f95c676f75674841aaf71888931a85206e9684030e1318"
   strings:
      $x1 = "-ExecutionPolicy Bypass -File \"" fullword wide
      $s2 = "NTdll.dll" fullword ascii
      $s3 = "shutdown.exe /f /s /t 0" fullword wide
      $s4 = "shutdown.exe /f /r /t 0" fullword wide
      $s5 = "shutdown.exe -L" fullword wide
      $s6 = "\\Log.tmp" fullword wide
      $s7 = "_appMutex" fullword ascii
      $s8 = "CloseMutex" fullword ascii
      $s9 = "XLogger" fullword ascii
      $s10 = "LoggerPath" fullword ascii
      $s11 = "userAgents" fullword ascii
      $s12 = "EXECUTION_STATE" fullword ascii
      $s13 = "GetHashT" fullword ascii
      $s14 = "POST / HTTP/1.1" fullword wide
      $s15 = "Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Saf" wide
      $s16 = "ProcessCritical" fullword ascii
      $s17 = "CriticalProcess_Enable" fullword ascii
      $s18 = "CriticalProcesses_Disable" fullword ascii
      $s19 = "SetCurrentProcessIsCritical" fullword ascii
      $s20 = "SystemEvents_SessionEnding" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_HVNC_HVNCMemory_9 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files HVNC.dll, HVNCMemory.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "3a287acb1c89692f2c18596dd4405089ac998bb9cf44dd225e5211923d421e96"
      hash2 = "285b462e3cd4a5b207315ad33ee6965a8b98ca58abb8d16882e4bc2d758ff1a4"
   strings:
      $s1 = "powershell.exe -c explorer shell:::{3080F90E-D7AD-11D9-BD98-0000947B0257}" fullword wide
      $s2 = "URLDownloadToFile" fullword ascii
      $s3 = "GetCurrentHwProfile" fullword ascii
      $s4 = "PowerShell: " fullword wide
      $s5 = "Methods.Native" fullword ascii
      $s6 = "SleepThread" fullword ascii
      $s7 = "DWLP_USER" fullword ascii
      $s8 = "MouseRightUp" fullword wide
      $s9 = "KeyboardDown" fullword wide
      $s10 = "MouseRightDown" fullword wide
      $s11 = "MouseRightUp :" fullword wide
      $s12 = "MouseRightDown :" fullword wide
      $s13 = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced" fullword wide
      $s14 = "Error: Explorer" fullword wide
      $s15 = "RemoteDesktopS" fullword wide
      $s16 = "Complete.///" fullword wide
      $s17 = "Running.////" fullword wide
      $s18 = "Yheight" fullword ascii
      $s19 = "TitleHandel2" fullword ascii
      $s20 = "Isgreaterorequalto81" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_HiddenApps_HVNC_HVNCMemory_10 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files HiddenApps.dll, HVNC.dll, HVNCMemory.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "6a098f5a7f9328b35d73ee232846b13e2d587d47f473cbc9b3f1d74def7086ea"
      hash2 = "3a287acb1c89692f2c18596dd4405089ac998bb9cf44dd225e5211923d421e96"
      hash3 = "285b462e3cd4a5b207315ad33ee6965a8b98ca58abb8d16882e4bc2d758ff1a4"
   strings:
      $s1 = "\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide
      $s2 = "Program Files\\Mozilla Firefox\\firefox.exe" fullword wide
      $s3 = "Program Files (x86)\\Mozilla Firefox\\firefox.exe" fullword wide
      $s4 = "Select * From Win32_Process Where ParentProcessID=" fullword wide
      $s5 = "CollectProcessAndChildren" fullword ascii
      $s6 = "m_lstProcessID" fullword ascii
      $s7 = "CommandPrompt" fullword ascii
      $s8 = "Cmd: Running" fullword wide
      $s9 = "\" --disable-3d-apis --disable-gpu --disable-d3d11 \"--user-data-dir=" fullword wide
      $s10 = "Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" fullword wide
      $s11 = "Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" fullword wide
      $s12 = "\" --mute-audio --disable-audio --disable-3d-apis --disable-gpu --disable-d3d11 \"--user-data-dir=" fullword wide
      $s13 = "Program Files\\Google\\Chrome\\Application\\chrome.exe" fullword wide
      $s14 = "Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe" fullword wide
      $s15 = "Program Files\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide
      $s16 = "Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide
      $s17 = "\" -no-remote -profile \"" fullword wide
      $s18 = "\\Mozilla\\Firefox\\FireFox Data" fullword wide
      $s19 = "get_DesktopHandle" fullword ascii
      $s20 = "fileNamePowerShell" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_SimpleObfuscator_Stealer_11 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files SimpleObfuscator.dll, Stealer.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "b7a6eea19188b987dad97b32d774107e9a1beb4f461a654a00197d73f7fad54c"
      hash2 = "018e06f57725563e4525700edffafb1b062bf5d4b0e9fee498507f0f8200fcdf"
   strings:
      $s1 = "get_PrivateExponent" fullword ascii
      $s2 = "get_PublicExponent" fullword ascii
      $s3 = "InvalidKeyException" fullword ascii
      $s4 = "get_Exponent1" fullword ascii
      $s5 = "get_Modulus" fullword ascii
      $s6 = "get_Coefficient" fullword ascii
      $s7 = "get_Exponent2" fullword ascii
      $s8 = "get_Prime1" fullword ascii
      $s9 = "get_Prime2" fullword ascii
      $s10 = "Exponent1" fullword ascii
      $s11 = "Exponent2" fullword ascii
      $s12 = "ParseBytes" fullword ascii
      $s13 = "AddCheckSum" fullword ascii
      $s14 = "WriteZeroes" fullword ascii
      $s15 = "recEnd" fullword ascii
      $s16 = "sigAlg" fullword ascii
      $s17 = "SHA_384" fullword ascii
      $s18 = "SHA_512" fullword ascii
      $s19 = "CalculateSignature" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_tg_Stealer_12 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files tg.exe, Stealer.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "90a7f859395ab46d284a0b4d9a9119cd499d06e7cc46ade4d1a5738e6fecd77b"
      hash2 = "018e06f57725563e4525700edffafb1b062bf5d4b0e9fee498507f0f8200fcdf"
   strings:
      $s1 = "Precompute" fullword ascii
      $s2 = "SupportedSignatureAlgorithms" fullword ascii
      $s3 = "extendedMasterSecret" fullword ascii
      $s4 = "supportedSignatureAlgorithms" fullword ascii
      $s5 = "ExportKeyingMaterial" fullword ascii
      $s6 = "NonceSize" fullword ascii
      $s7 = "SigEd25519 no Ed25519 collisions" fullword ascii
      $s8 = "IsTimeout" fullword ascii
      $s9 = "ProbablyPrime" fullword ascii
      $s10 = "AddCert" fullword ascii
      $s11 = "secureRenegotiation" fullword ascii
      $s12 = "InhibitAnyPolicy" fullword ascii
      $s13 = "validPolicy" fullword ascii
      $s14 = "Primes" fullword ascii
      $s15 = "certificateAuthorities" fullword ascii
      $s16 = "Reseed" fullword ascii
      $s17 = "SubOne" fullword ascii
      $s18 = "ScalarMult" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 31000KB and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_Chromium_Recovery_13 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files Chromium.dll, Recovery.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "b6d8bccdf123ceac6b9642ad3500d4e0b3d30b9c9dd2d29499d38c02bd8f9982"
      hash2 = "66dbe3b90371fe58caa957e83c1c1f0acce941a36cf140a0f07e64403dd13303"
   strings:
      $s1 = "BCrypt.BCryptDecrypt() (get size) failed with status code: {0}" fullword wide
      $s2 = "BCrypt.BCryptGetProperty() (get size) failed with status code:{0}" fullword wide
      $s3 = "BCrypt.BCryptGetProperty() failed with status code:{0}" fullword wide
      $s4 = "BCrypt.BCryptImportKey() failed with status code:{0}" fullword wide
      $s5 = "BCrypt.BCryptDecrypt() failed with status code:{0}" fullword wide
      $s6 = "\"encrypted_key\":\"(.*?)\"" fullword wide
      $s7 = "BCRYPT_INIT_AUTH_MODE_INFO_VERSION" fullword ascii
      $s8 = "BCrypt.BCryptOpenAlgorithmProvider() failed with status code:{0}" fullword wide
      $s9 = "BCrypt.BCryptSetAlgorithmProperty(BCrypt.BCRYPT_CHAINING_MODE, BCrypt.BCRYPT_CHAIN_MODE_GCM) failed with status code:{0}" fullword wide
      $s10 = "DecryptWithKey" fullword ascii
      $s11 = "BCrypt.BCryptDecrypt(): authentication tag mismatch" fullword wide
      $s12 = "BCRYPT_KEY_LENGTHS_STRUCT" fullword ascii
      $s13 = "BCRYPT_KEY_DATA_BLOB" fullword ascii
      $s14 = "ReadTableFromOffset" fullword ascii
      $s15 = "BCRYPT_KEY_DATA_BLOB_MAGIC" fullword ascii
      $s16 = "authTag" fullword ascii
      $s17 = "pbAuthData" fullword ascii
      $s18 = "pbKeyObject" fullword ascii
      $s19 = "MaxAuthTagSize" fullword ascii
      $s20 = "ReadMasterTable" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_HBrowser_HiddenApps_14 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files HBrowser.dll, HiddenApps.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "75e8ff57fa6d95cf4d8405bffebb2b9b1c55a0abba0fe345f55b8f0e88be6f3c"
      hash2 = "6a098f5a7f9328b35d73ee232846b13e2d587d47f473cbc9b3f1d74def7086ea"
   strings:
      $s1 = "SELECT ProcessId, ExecutablePath FROM Win32_Process WHERE ProcessId = " fullword wide
      $s2 = "An error occurred while importing the list of windows" fullword wide
      $s3 = "MsgLogs" fullword ascii
      $s4 = "get_WindowrActive" fullword ascii
      $s5 = "GetMainModuleFilepath" fullword ascii
      $s6 = "GetListWindow" fullword ascii
      $s7 = "get_IsWindowActived" fullword ascii
      $s8 = "GetHWND" fullword wide
      $s9 = " window is ready" fullword wide
      $s10 = "FrameChanged" fullword ascii
      $s11 = "keyboardClick" fullword wide
      $s12 = "Error! " fullword wide
      $s13 = "get_Resize" fullword ascii
      $s14 = "Appsstream" fullword ascii
      $s15 = "ResizeWondow" fullword ascii
      $s16 = "WindowCheck" fullword ascii
      $s17 = "DoNotReposition" fullword ascii
      $s18 = "<IsWindowActived>k__BackingField" fullword ascii
      $s19 = "IndexWindow" fullword ascii
      $s20 = "DoNotSendChangingEvent" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_WSound_Microphone_15 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files WSound.dll, Microphone.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "4bea01b7d691d1f59ca0bb5149e5baf71cde71019da3d352141b1d4921e70bc2"
      hash2 = "612898afdf9120cfef5843f9b136c66ecc3e0bb6f3d1527d0599a11988b7783c"
   strings:
      $s1 = "sourcestream" fullword ascii
      $s2 = "audioDataAvailable" fullword ascii
      $s3 = "OW*r28" fullword ascii
      $s4 = "[j*r,1" fullword ascii
      $s5 = "j[*r,1" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_Newtonsoft_Json_Guna_UI2_16 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files Newtonsoft.Json.dll, Guna.UI2.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "e1e27af7b07eeedf5ce71a9255f0422816a6fc5849a483c6714e1b472044fa9d"
      hash2 = "c6264665a882e73eb2262a74fea2c29b1921a9af33180126325fb67a851310ef"
   strings:
      $s1 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii
      $s2 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii
      $s3 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii
      $s4 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii
      $s5 = "http://ocsp.digicert.com0X" fullword ascii
      $s6 = "Ihttp://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl0" fullword ascii
      $s7 = "Lhttp://cacerts.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crt0" fullword ascii
      $s8 = "DigiCert Timestamp 2022 - 20" fullword ascii
      $s9 = "DigiCert1$0\"" fullword ascii
      $s10 = "DigiCert, Inc.1;09" fullword ascii
      $s11 = "2DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA0" fullword ascii
      $s12 = "2DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA" fullword ascii
      $s13 = "311109235959" ascii
      $s14 = "220801000000Z" fullword ascii
      $s15 = "331121235959Z0F1" fullword ascii
      $s16 = "220921000000Z" fullword ascii
      $s17 = "~qj#k\"" fullword ascii
      $s18 = "(f*^[0" fullword ascii
      $s19 = "220323000000Z" fullword ascii
      $s20 = "370322235959" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_noanti_Wiz_XClient_1_Keylogger_XClient_2_installer_17 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files noanti.exe, Wiz.exe, XClient.exe, 1.exe, Keylogger.dll, XClient-2.exe, installer.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "cbfd0dba27e9818a322ac849f0f6321675e97ac82a63ed3805cd3a5b84b3948f"
      hash2 = "4282a3625eeb9d921474ed4f35b3632ccb69e5f951166b9200ac6ee2d42ea493"
      hash3 = "4a1f05acef115eaeffcf2382a9816f6d86a160515ba2d3949eb5215e03f87209"
      hash4 = "b708f2ed06dee2fb99250a733323b939bcaad7da59b0d21a5cf314f3cc926452"
      hash5 = "acfe5c3aa2a3bae3437ead42e90044d7eee972ead25c1f7486bea4a23c201d3a"
      hash6 = "dd8f5088a7d6c1e18a5a4d3a64a309dd981280adcbc0b4ec343019a5d540b518"
      hash7 = "ad02d29c876bb868e3f95c676f75674841aaf71888931a85206e9684030e1318"
   strings:
      $s1 = "WHKEYBOARDLL" fullword ascii
      $s2 = "GetActiveWindowTitle" fullword ascii
      $s3 = "LowLevelKeyboardProc" fullword ascii
      $s4 = "CurrentActiveWindowTitle" fullword ascii
      $s5 = "_hookID" fullword ascii
      $s6 = "[ENTER]" fullword wide
      $s7 = "[Back]" fullword wide
      $s8 = "HookCallback" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and ( all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_super_rule_1 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files VoiceChat.dll, Chromium.dll, WebCam.dll, UACBypass.dll, noanti.exe, Wiz.exe, HVNC.dll, Performance.dll, XClient.exe, Ngrok-Installer.dll, Cmstp-Bypass.dll, Options.dll, VB.NET Compiler.dll, Ransomware.dll, 1.exe, FileManager.dll, Chat.dll, Clipboard.dll, Shell.dll, Regedit.dll, Keylogger.dll, Informations.dll, MessageBox.dll, ServiceManager.dll, ActiveWindows.dll, Pastime.dll, Maps.dll, StartupManager.dll, RunPE.dll, ProcessManager.dll, HRDP.dll, TCPConnections.dll, XClient-2.exe, installer.exe, Programs.dll, WSound.dll, ReverseProxy.dll, Microphone.dll, RemoteDesktop.dll, FilesSearcher.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "1a2da0a66c7771962d525b8fe9491052efbd5f87b97d935c267fd96519b5a35e"
      hash2 = "b6d8bccdf123ceac6b9642ad3500d4e0b3d30b9c9dd2d29499d38c02bd8f9982"
      hash3 = "8d413b40aef41e53557d91f3b3ac64cfc13adb0f8c3edc364e7b8501170e2657"
      hash4 = "ebd51f1e33673cb8e55f10aa890a04027d62b1c1c0b0ae9b1d6f83f1602f53a2"
      hash5 = "cbfd0dba27e9818a322ac849f0f6321675e97ac82a63ed3805cd3a5b84b3948f"
      hash6 = "4282a3625eeb9d921474ed4f35b3632ccb69e5f951166b9200ac6ee2d42ea493"
      hash7 = "3a287acb1c89692f2c18596dd4405089ac998bb9cf44dd225e5211923d421e96"
      hash8 = "043b6a0284468934582819996dbaa70b863ab4caa4f968c81c39a33b2ac81735"
      hash9 = "4a1f05acef115eaeffcf2382a9816f6d86a160515ba2d3949eb5215e03f87209"
      hash10 = "b574aabf02a65aa3b6f7bfff0a574873ce96429d3f708a10f87bc1f6518f14aa"
      hash11 = "fa420fd3d1a5a2bb813ef8e6063480099f19091e8fa1b3389004c1ac559e806b"
      hash12 = "5c34aee5196e0f8615b8d1d9017dd710ea28d2b7ac99295d46046d12eea58d78"
      hash13 = "1940d563046c67dbbeaf5f2a2417aaccdae587c1eb97b79c263994896805bece"
      hash14 = "14c2bbccdabb8408395d636b44b99de4b16db2e6bf35181cb71e7be516d83ad9"
      hash15 = "b708f2ed06dee2fb99250a733323b939bcaad7da59b0d21a5cf314f3cc926452"
      hash16 = "b58ed3ebbcd27c7f4b173819528ff4db562b90475a5e304521ed5c564d39fffd"
      hash17 = "aab20f465955d77d6ec3b5c1c5f64402a925fb565dda5c8e38c296cb7406e492"
      hash18 = "e31a1c2b1baa2aa2c36cabe3da17cd767c8fec4c206bd506e889341e5e0fa959"
      hash19 = "6c69b4d45638097e31169d94914e4acb6a8cc7f46788ffa4f241e4c1efb213bb"
      hash20 = "2f73dc0f3074848575c0408e02079fd32b7497f8816222ae3ce8c63725a62fe6"
      hash21 = "acfe5c3aa2a3bae3437ead42e90044d7eee972ead25c1f7486bea4a23c201d3a"
      hash22 = "cba453460be46cfa705817abbe181f9bf65dca6b6cea1ad31629aa08dbeaf72b"
      hash23 = "bc09b671894c9a36f4eca45dd6fbf958a967acea9e85b66c38a319387b90dd29"
      hash24 = "c552d11db168a4f64db584283a617a6ec51ab6095c20ba4b706c3138beb68a22"
      hash25 = "567b9861026a0dbc5947e7515dc7ab3f496153f6b3db57c27238129ec207fc52"
      hash26 = "a46787527ac34cd71d96226ddfc0a06370b61e4ad0267105be2aec8d82e984c1"
      hash27 = "34b532a4d0560e26b0d5b81407befdc2424aacc9ef56e8b13de8ad0f4b3f1ab6"
      hash28 = "1802e16379d96021fee05f583633c8091bb669350b7d32064179a8944d45a5a6"
      hash29 = "7adfe849345edd76aa975b0647fed2ccaa5f4a6aaf7d55f488af939c0dbef153"
      hash30 = "7cf1921a5f8429b2b9e8197de195cfae2353fe0d8cb98e563bdf1e782fe2ee4e"
      hash31 = "4aa18745a5fddf7ec14adaff3ad1b4df1b910f4b6710bf55eb27fb3942bb67de"
      hash32 = "27e17a43478448f64107df786a170753dbd116eafca7c027f6d357f11e6a4def"
      hash33 = "dd8f5088a7d6c1e18a5a4d3a64a309dd981280adcbc0b4ec343019a5d540b518"
      hash34 = "ad02d29c876bb868e3f95c676f75674841aaf71888931a85206e9684030e1318"
      hash35 = "953a8276faa4a18685d09cd9187ed3e409e3cccd7daf34b6097f1eb8d96125a4"
      hash36 = "4bea01b7d691d1f59ca0bb5149e5baf71cde71019da3d352141b1d4921e70bc2"
      hash37 = "8c4efe2c8702141ffa8ff8f55d248dc4220231ae8d12ecea1f22906a9285b32b"
      hash38 = "612898afdf9120cfef5843f9b136c66ecc3e0bb6f3d1527d0599a11988b7783c"
      hash39 = "cc52384910cee944ddbcc575a8e0177bfa6b16e3032438b207797164d5c94b34"
      hash40 = "e66e1273dc59ee9e05ce3e02f1b760b18dd296a47d92b3ce5b24efb48e5fb21b"
   strings:
      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s2 = "My.Computer" fullword ascii
      $s3 = "MyTemplate" fullword ascii
      $s4 = "My.WebServices" fullword ascii
      $s5 = "m_UserObjectProvider" fullword ascii
      $s6 = "ThreadSafeObjectProvider`1" fullword ascii
      $s7 = "MyWebServices" fullword ascii
      $s8 = "m_MyWebServicesObjectProvider" fullword ascii
      $s9 = "m_ComputerObjectProvider" fullword ascii
      $s10 = "MyProject" fullword ascii
      $s11 = "My.User" fullword ascii
      $s12 = "Dispose__Instance__" fullword ascii
      $s13 = "m_AppObjectProvider" fullword ascii
      $s14 = "Create__Instance__" fullword ascii
      $s15 = "MyApplication" fullword ascii
      $s16 = "My.Application" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_Wiz_1_XClient_2_19 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files Wiz.exe, 1.exe, XClient-2.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "4282a3625eeb9d921474ed4f35b3632ccb69e5f951166b9200ac6ee2d42ea493"
      hash2 = "b708f2ed06dee2fb99250a733323b939bcaad7da59b0d21a5cf314f3cc926452"
      hash3 = "dd8f5088a7d6c1e18a5a4d3a64a309dd981280adcbc0b4ec343019a5d540b518"
   strings:
      $s1 = "*.* /s /d" fullword wide
      $s2 = "attrib -h -s " fullword wide
      $s3 = "regread" fullword wide
      $s4 = "windowstyle" fullword wide
      $s5 = "USBThread" fullword ascii
      $s6 = "\\defaulticon\\" fullword wide
      $s7 = "USBStart" fullword ascii
      $s8 = "USBStop" fullword ascii
      $s9 = "USBCode" fullword ascii
      $s10 = "/c start " fullword wide
      $s11 = "iconlocation" fullword wide
      $s12 = "&start explorer " fullword wide
      $s13 = "HKEY_LOCAL_MACHINE\\software\\classes\\" fullword wide
      $s14 = "HKEY_LOCAL_MACHINE\\software\\classes\\." fullword wide
      $s15 = "HKEY_LOCAL_MACHINE\\software\\classes\\folder\\defaulticon\\" fullword wide
      $s16 = "&start " fullword wide
      $s17 = " & exit" fullword wide
      $s18 = "IconLocation" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_noanti_Wiz_XClient_XClient_2_installer_20 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files noanti.exe, Wiz.exe, XClient.exe, XClient-2.exe, installer.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "cbfd0dba27e9818a322ac849f0f6321675e97ac82a63ed3805cd3a5b84b3948f"
      hash2 = "4282a3625eeb9d921474ed4f35b3632ccb69e5f951166b9200ac6ee2d42ea493"
      hash3 = "4a1f05acef115eaeffcf2382a9816f6d86a160515ba2d3949eb5215e03f87209"
      hash4 = "dd8f5088a7d6c1e18a5a4d3a64a309dd981280adcbc0b4ec343019a5d540b518"
      hash5 = "ad02d29c876bb868e3f95c676f75674841aaf71888931a85206e9684030e1318"
   strings:
      $s1 = "intpreclp" fullword ascii
      $s2 = "_Lambda$__9" fullword ascii
      $s3 = "ClipboardFunc" fullword ascii
      $s4 = "_Closure$__3" fullword ascii
      $s5 = "_Lambda$__11" fullword ascii
      $s6 = "TRCRegex" fullword ascii
      $s7 = "currentClipboard" fullword ascii
      $s8 = "_Lambda$__10" fullword ascii
      $s9 = "ETHRegex" fullword ascii
      $s10 = "BTCRegex" fullword ascii
      $s11 = "RegexResult" fullword ascii
      $s12 = "_Closure$__2" fullword ascii
      $s13 = "BTC Clipper " fullword wide
      $s14 = "ETH Clipper " fullword wide
      $s15 = "TRC20 Clipper " fullword wide
      $s16 = "ExStyle" fullword wide
      $s17 = "$VB$Local_txt" fullword ascii
      $s18 = "\\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,45}\\b" fullword wide
      $s19 = "\\b(0x)[a-zA-HJ-NP-Z0-9]{40,45}\\b" fullword wide
      $s20 = "T[A-Za-z1-9]{33}" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_HVNC_RunPE_21 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files HVNC.dll, RunPE.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "3a287acb1c89692f2c18596dd4405089ac998bb9cf44dd225e5211923d421e96"
      hash2 = "7adfe849345edd76aa975b0647fed2ccaa5f4a6aaf7d55f488af939c0dbef153"
   strings:
      $s1 = "processAttributes" fullword ascii
      $s2 = "StdInput" fullword ascii
      $s3 = "StdError" fullword ascii
      $s4 = "threadAttributes" fullword ascii
      $s5 = "HandleRun" fullword ascii
      $s6 = "StdOutput" fullword ascii
      $s7 = "STARTUP_INFORMATION" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_noanti_XClient_1_XClient_2_installer_22 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files noanti.exe, XClient.exe, 1.exe, XClient-2.exe, installer.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "cbfd0dba27e9818a322ac849f0f6321675e97ac82a63ed3805cd3a5b84b3948f"
      hash2 = "4a1f05acef115eaeffcf2382a9816f6d86a160515ba2d3949eb5215e03f87209"
      hash3 = "b708f2ed06dee2fb99250a733323b939bcaad7da59b0d21a5cf314f3cc926452"
      hash4 = "dd8f5088a7d6c1e18a5a4d3a64a309dd981280adcbc0b4ec343019a5d540b518"
      hash5 = "ad02d29c876bb868e3f95c676f75674841aaf71888931a85206e9684030e1318"
   strings:
      $s1 = "\\drivers\\etc\\hosts" fullword wide
      $s2 = "RunShell" fullword wide
      $s3 = "HostsMSG" fullword wide
      $s4 = "HostsErr" fullword wide
      $s5 = "Shosts" fullword wide
      $s6 = "InstallStr" fullword ascii
      $s7 = "IsValidDomainName" fullword ascii
      $s8 = "ActivatePong" fullword ascii
      $s9 = "Modified successfully!" fullword wide
      $s10 = "RemovePlugins" fullword wide
      $s11 = "Plugins Removed!" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 8 of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_Ransomware_FileManager_23 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files Ransomware.dll, FileManager.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "14c2bbccdabb8408395d636b44b99de4b16db2e6bf35181cb71e7be516d83ad9"
      hash2 = "b58ed3ebbcd27c7f4b173819528ff4db562b90475a5e304521ed5c564d39fffd"
   strings:
      $s1 = "EncryptOrDecryptFile" fullword ascii
      $s2 = "ActionEncrypt" fullword ascii
      $s3 = "ActionDecrypt" fullword ascii
      $s4 = "bytKey" fullword ascii
      $s5 = "fuWinIni" fullword ascii
      $s6 = "strOutputFile" fullword ascii
      $s7 = "fsOutput" fullword ascii
      $s8 = "strInputFile" fullword ascii
      $s9 = "CryptoAction" fullword ascii
      $s10 = "fsInput" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_HBrowser_HiddenApps_HVNC_HVNCMemory_24 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files HBrowser.dll, HiddenApps.dll, HVNC.dll, HVNCMemory.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "75e8ff57fa6d95cf4d8405bffebb2b9b1c55a0abba0fe345f55b8f0e88be6f3c"
      hash2 = "6a098f5a7f9328b35d73ee232846b13e2d587d47f473cbc9b3f1d74def7086ea"
      hash3 = "3a287acb1c89692f2c18596dd4405089ac998bb9cf44dd225e5211923d421e96"
      hash4 = "285b462e3cd4a5b207315ad33ee6965a8b98ca58abb8d16882e4bc2d758ff1a4"
   strings:
      $s1 = "KeysLParam" fullword ascii
      $s2 = "CreateLParamFor_WM_KEYUP" fullword ascii
      $s3 = "KeyboardDown" fullword ascii
      $s4 = "CreateLParamFor_WM_KEYDOWN" fullword ascii
      $s5 = "DownBefore" fullword ascii
      $s6 = "HandleClipboard" fullword ascii
      $s7 = "CustomOpen" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_noanti_XClient_installer_25 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files noanti.exe, XClient.exe, installer.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "cbfd0dba27e9818a322ac849f0f6321675e97ac82a63ed3805cd3a5b84b3948f"
      hash2 = "4a1f05acef115eaeffcf2382a9816f6d86a160515ba2d3949eb5215e03f87209"
      hash3 = "ad02d29c876bb868e3f95c676f75674841aaf71888931a85206e9684030e1318"
   strings:
      $x1 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionProcess '" fullword wide
      $x2 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionPath '" fullword wide
      $s3 = "JAKt>6," fullword ascii
      $s4 = "5N,%tN+%y," fullword ascii
      $s5 = "4a91h|J>" fullword ascii
      $s6 = "}@3HA " fullword ascii
      $s7 = "m<4fg91P" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_HBrowser_HVNC_HVNCMemory_26 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files HBrowser.dll, HVNC.dll, HVNCMemory.dll"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "75e8ff57fa6d95cf4d8405bffebb2b9b1c55a0abba0fe345f55b8f0e88be6f3c"
      hash2 = "3a287acb1c89692f2c18596dd4405089ac998bb9cf44dd225e5211923d421e96"
      hash3 = "285b462e3cd4a5b207315ad33ee6965a8b98ca58abb8d16882e4bc2d758ff1a4"
   strings:
      $s1 = "MouseRghitUp" fullword ascii
      $s2 = "MouseRightDown" fullword ascii
      $s3 = "MouseLeftUp" fullword ascii
      $s4 = "MouseLeftDown" fullword ascii
      $s5 = "IsCloseHandel" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and pe.imphash() == "dae02f32a21e03ce65412f6e56942daa" and ( all of them )
      ) or ( all of them )
}

rule MAL_BETRAY_XWORM_AUG25_Wiz_1_27 {
   meta:
      description = "MAL_BETRAY_XWORM_AUG25 - from files Wiz.exe, 1.exe"
      author = "DeTraced Security"
      reference = "https://detraced.org/posts/infostealer-turned-ransomware"
      date = "2025-10-17"
      hash1 = "4282a3625eeb9d921474ed4f35b3632ccb69e5f951166b9200ac6ee2d42ea493"
      hash2 = "b708f2ed06dee2fb99250a733323b939bcaad7da59b0d21a5cf314f3cc926452"
   strings:
      $s1 = "/create /f /RL HIGHEST /sc minute /mo 1 /tn \"" fullword wide
      $s2 = "/create /f /sc minute /mo 1 /tn \"" fullword wide
      $s3 = "/delete /f  /tn \"" fullword wide
      $s4 = "schtasks" fullword wide
      $s5 = "\" /tr \"" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and ( all of them )
      ) or ( all of them )
}

