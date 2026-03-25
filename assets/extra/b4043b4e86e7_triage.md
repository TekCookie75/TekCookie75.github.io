# Malware Triage Report

**File:** `evil3.exe`  
**SHA-256:** `b4043b4e86e7591012251410ec5408360c03f479165580c22cf116bd4d0c9eae`  
**Analysis Date:** 2026-03-24 13:57 UTC  

> ⚠️ This report was produced using **static analysis only**. The sample was never executed.

---

## File Meta-Data

| Field | Value |
|---|---|
| File Name | `evil3.exe` |
| File Size | 80,384 bytes |
| MD5 | `88a95686ccbdaf9365aaa73b4d46abb9` |
| SHA-1 | `fb56944f8ab9d173344818c31e044050e2983e54` |
| SHA-256 | `b4043b4e86e7591012251410ec5408360c03f479165580c22cf116bd4d0c9eae` |
| Architecture | PE32 |
| Image Base | `0x00400000` |
| Entry Point | `0x000103CB` |
| VirusTotal | 0 malicious, 0 suspicious / ? engines — [View on VirusTotal](https://www.virustotal.com/gui/file/b4043b4e86e7591012251410ec5408360c03f479165580c22cf116bd4d0c9eae) |
| VT Threat Label | N/A |
| VT First Seen | N/A |
| VT Tags | none |

### PE Sections

| Section | Size (bytes) | Entropy | Flag |
|---|---|---|---|
| `.text` | 76,288 | 6.569 | ⚠️ HIGH ENTROPY |
| `.data` | 512 | 3.2856 |  |
| `.reloc` | 2,560 | 6.4164 |  |

---

## Imports / Exports

### Suspicious Imports (0 hits)

_No suspicious imports detected._

### All Imported DLLs

| DLL | Import Count |
|---|---|

### Exports & TLS Callbacks

| Type | RVA | Name |
|---|---|---|
| — | — | No exports or TLS callbacks found |

---

## Relevant IoCs

> Strings extracted by **floss** and filtered to length ≥ 6 chars and entropy < 6.5.  
> **374** strings kept from **844** total (470 filtered out).

### Network Indicators

- `http://%s`
- `https://%S/a/%S`
- `176.126.70.119`
- `http://benten02.futbol`
- `/c ping 127.0.0.1 && del "%s"`

### File System Paths

_None found._

### Registry Keys

_None found._

### Other Strings

- `8|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\]^_`abcdefghijklmnopq`
- `Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`
- `Content-Type: application/x-www-form-urlencoded`
- `{53F49750-6209-4FBF-9CA8-7A333C87D1ED}_is1`
- `com.liberty.jaxx\IndexedDB\file__0.indexeddb.leveldb\3.log`
- `!This program cannot be run in DOS mode.`
- `GHISLER\wcx_ftp.ini`
- `discord\Local Storage\https_discordapp.com_0.localstorage`
- `Software\Microsoft\Office\%d.0\Outlook\Profil`
- `Internet Explorer\TypedURLs`
- `Martin Prikryl\WinSCP 2\Sessions`
- `Ipswitch\WS_FTP\Sites\ws_ftp.ini`
- `Internet Explorer\IntelliForms\Storage2`
- `\]^_XYZ[TU-./()*`
- `te1Tia}~ctcMEhatuDC]b`
- `Content-Type: application/octet-stream`
- `ghijkklmnopqrstuv`
- `/QU6M6L2o04P9gIbD`
- `Windows NT\CurrentVersion`
- `Q}|fw|f?Fkbw(2sbb~{qsf{}|=}qfwf?af`ws`
- `xFAK@X\slZ]]JA[yJ]\F@AszAFA\[NCC`
- `Windows\CurrentVersion\Uninstall`
- `Q}|fw|f?W|q}v{|u(2p{|s`k`
- `Content-Encoding: binary`
- `abe2869f-9b47-4cd9-a358-c22904dba7f7`
- `MachineGuid: %S`
- `4gYVQPbxgHVf1ldk`
- `Microsoft_WinInet_*`
- `setting[@name='%s']`
- `1|TotalCommander|%s|%s|%s`
- `CPU: %s (%d cores)`
- `%SContent-Length: %d`
- `SQLite format 3`
- `encryptedPassword`
- `formhistory.sqlite`
- `1=2^3~4"7-7q7b9`
- `>`BMP STRING`
- `webappsstore.sqlite`
- `password-check`
- `\qkhtyaN}jkqwv`
- `)8**.6+=ylhc;c`
- `DisplayVersion`
- `UNIVERSAL STRING`
- `PRINTABLE STRING`
- `OBJECT DESCRIPTOR`
- `4|Remote Desktop|%s|%s|%s`
- `LT: %s (UTC+%d:%d)`
- `jHU^OYNt[W_`
- `user.config`
- `DisplayIcon`
- `ProductName`
- `VIDEOTEXT STRING`
- `netapi32.dll`
- `accounts.xml`
- `password 51🅱`
- `OBJECT IDENTIFIER`
- `IMAP Password`
- `SMTP Password`
- `encryptedUsername`
- `2|EarthVPN||%s|%s`
- `GRAPHIC STRING`
- `NUMERIC STRING`
- `screenshot.png`
- `GENERALIZED TIME`
- `HTTP Server URL`
- `9K:J;7<o<w<F=`
- `CHARACTER STRING`
- `IMPAUTOFILL_DATA`
- `1|FileZilla|%s:%s|%s|%S`
- `VISIBLE STRING`
- `%s\Outlook.txt`
- `UTF8String`
- `[|fw`|wf2Wjb~}`w``
- `Internet Explorer`
- `Internet Explorer`
- `?.%,(onr800`
- `pstorec.dll`
- `crypt32.dll`
- `DisplayName`
- `%S/gate.php`
- `MachineGuid`
- `RELATIVE-OID`
- `HTTP Password`
- `Screen: %dx%d`
- `GENERAL STRING`
- `SYSINFORMATION`
- `%S %s HTTP/1.1`
- `cookies.sqlite`
- `full address:s:`
- `OCTET STRING`
- `oleaut32.dll`
- `*--:1+\t:-,601`
- `monero-project`
- `signons.sqlite`
- `POP3 Password`
- `IA5String`
- `IMAP User`
- `SMTP User`
- `M\#u/P<iV`
- `Software:`
- `23456789A`
- `%S/gate.p`
- `2|NordVPN||%s|%s`
- `user32.dll`
- `Login Data`
- `loginusers`
- `UTC STRING`
- `1|WS_FTP|%s|%s|%S`
- `Valve\Steam`
- `%s\key%d.db`
- `mk}j}vn6|tt`
- `$>#2:69602%`
- `ProhibitDTD`
- `IMAP Server`
- `winhttp.dll`
- `userenv.dll`
- `sitemanager`
- `%s\.purple\%s`
- `advapi32.dll`
- `uoh`itkgroih`
- `Cryptography`
- `=+3,7($}+$}+$}+UR`
- `1|WinSCP|%s|%s|%s`
- `%s: %s | %02d/%04d | %s`
- `shlwapi.dll`
- `AUTOFILL_DATA`
- `Z}af(27A`
- `]zfa[txp`
- `mor{tqxn`
- `*.config`
- `Hostname`
- `Software`
- `Layouts:`
- `Software`
- `Host: %S`
- `HostName`
- `Electrum`
- `EarthVPN`
- `profiles`
- `s\Outlook`
- `vRXITHT]O`
- `HTTP User`
- `POP3 User`
- `SMTP Port`
- `IMAP Port`
- `dotbit.me`
- `%NETWORK%`
- `Microsoft`
- `Microsoft`
- `accounts.`
- `3|Pidgin|%s|%s|%s`
- `BIT STRING`
- `RAM: %s MB`
- `ws2_32.dll`
- `%FULLDISK%`
- `dnsapi.dll`
- `%s\%S.json`
- `vaultcli.dll`
- `~`g`gl}'mee`
- `tboofw\sbwk`
- `rtbuifjb=t=`
- `SMTP Server`
- `POP3 Server`
- `CREDIT_CARD`
- `wininet.dll`
- `InstallPath`
- `%s\%s\%s\%.6s_%d.dat`
- `3|Psi(+)|%s|%s|%s`
- `ENUMERATED`
- `urlmon.dll`
- `gdiplus.dll`
- `r^\bATR`
- `;7?9534`
- `%,*=;<$`
- `09+(>-:`
- `-0963:,`
- `5283+/|`
- `<5'$2!6`
- `Y<@uq9}`
- `Y< u^9}`
- `Y< uK9}`
- `v\tN+D$`
- `key3.db`
- `Login D`
- `key4.db`
- `Usernam`
- `main.db`
- `%s | %02d/%04d | %s | %s | %s`
- `EXTERNAL`
- `IBOCHEBK`
- `SDPIQFIL`
- `6<-0,09+`
- `*=,&,+:2`
- `XZZVLWMJ`
- `kZSZXM^R`
- `*.wallet`
- `Web Data`
- `User: %s`
- `UserName`
- `Password`
- `Ethereum`
- `Username`
- `encoding`
- `shell32.dll`
- `%s\tTRUE\t%s\t%s\t%d\t%s\t%s`
- `<n=8>B><?`
- `:(<2<A=K=`
- `%s\%s.vdf`
- `gdi32.dll`
- `Battle.ne`
- `wallet.dat`
- `3$3,343<3D3L3T3\3d3l3t3|3`
- `5$5,545<5D5L5T5\5d5l5t5|5`
- `6$6,646<6D6L6T6\6d6l6t6|6`
- `7$7,747<7D7L7T7\7d7l7t7|7`
- `1 1$1(1,1014181<1@1D1H1L1`
- `MwX]TkX]]PM`
- `wininet.txt`
- `connections`
- `pktvpkt}vktqs`
- `%08lX%04lX%lu`
- `POP3 Port`
- `ole32.dll`
- `%s\%s\%s.xml`
- `%s\%s\%s.vdf`
- `'! 8'$ 8!&8''/`
- `%02d-%02d-%02d %d:%02d:%02d`
- `8,8:8H8V8`8j8N;`
- `.reloc`
- `\[EDFG`
- `7$!NTQ`
- `Roxsbd`
- `@B_ZGV`
- `61;0(,`
- `61;0(,`
- `9./532`
- `46=<;0`
- `6{wv~q`
- `>:6/=9`
- `98t<SV`
- `PVh`8@`
- `<\t_^[`
- `tAj/Yf`
- `s<Wj@h`
- `PSh49@`
- `PSj\t^`
- `QSVWj(`
- `User32`
- `wx0tQA`
- `logins`
- `Crypto`
- `config`
- `Exodus`
- `4#%#(25#40#45`
- `recentservers`
- `EMBEDDED PDV`
- `strDataDir`
- `BOOLEAN`
- `Q/(wQGP`
- `Nbbfdh~`
- `9):JX69`
- `a?:=?#*`
- `9 :n:L;`
- `%08x.%s`
- `NordVPN`
- `Cookies`
- `INTEGER`
- `kvt(bjj`
- `mpr.dll`
- `4$4,444<4D4L4T4\4d4l4t4|4`
- `%s\%s.txt`
- `:,,>8618`
- `GkR_\RUG`
- `z~a~zavwavx`
- `}RW^aRWWZ`
- `FileZilla`
- `%s\%s\%s-Qt`
- `SEQUENCE`
- `: :7:L🅰i:n:`
- `))1$7443$))`
- `__GRABBER__`
- `__DELIMM__`
- `?6; ?<? ?99 ?99`
- `4L5V5j5v5`
- `<3=D=s=z=`
- `2 3D3]3u3`
- `3 4/4H4w4`
- ``.data`
- `*+3004`
- `FVWSSj`
- `4\t5S5`
- `)..92(`
- `=57,=x`
- `%S x%d`
- `%s(%S)`
- `tFj\j/`
- `<SWj<_`
- `<SWj<_`
- `\?\%c:`
- `%s: %d`
- `DPAPI:`
- `Battle`
- `@ZT]\]@`
- `A,3A$3U`
- `A83A,3U`
- `A<3A43U`
- `A83A$3U`
- `YYt\tSW`
- `Grabber`
- `?)?5?A?M?Y?w?`
- `)p&)p&)p&X_`
- `0-1[1u1`
- `;#<?<[<`
- `6U8b8r8`
- `:,;>;L;`
- `:2;G;m;`
- `4"5L5c5`
- `%s\%s\%.6ss`
- `0|%S|%s|%s|%s`
- `0|%s|%S|%s|%s`
- `;";6;J;^;r;`
- `<&<:<N<b<v<`
- `=*=>=R=f=z=`
- `>.>B>V>j>~>`
- `0*080L0`0t0`
- `1(1<1P1d1x1`
- `2,2@2T2h2|2`
- `3*3>3R3f3z3`
- `4.4B4V4j4~4`
- `525F5Z5n5|5`
- `7"707>7H7R7`
- `5$5P5h5q5z5`
- `8E8d8l8r8}8`
- `%s | %s | %s | %s | %s | %s | %s | %d | %s`
- `ISWVVVVj`
- `(0P0x0|0`
- `%s | %s | %s`
- `%s = %s`
- `%s: %s`
- `%S\%S\%s`
- `799R9e9s9`
- `<8<M<e<x<`
- `=B=U=i=t=`
- `:2:F:Z:n:`
- `?2?F?Z?n?`
- `>'>0>7>C>`
- `5!5E5W5u5`
- `:':T:l:v:`
- `9+9H9`9y9`
- `0|%s|%s|%s|%s`
- `A,3A$3A`
- `A83A,3A`
- `A83A,3A`
- `FFFILEE`
- `l2t2|2`
- `?>?Q?q?`
- `0,0:0a0`
- `3/353{3`
- `7(7Q7s7`
- `808U8w8`
- `=,=:=v=`
- `9F9c9u9`
- `%s\%s\%s\%s`
- `%s\%s\%s`
- `YSSSPS`
- `%33333`
- `%33333`
- `PVVVVVV`
- `VVVVVV`
