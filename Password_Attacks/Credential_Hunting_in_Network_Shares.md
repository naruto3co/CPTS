# Săn Lùng Thông Tin Đăng Nhập Trong Network Shares

*(Credential Hunting in Network Shares | Hack The Box Academy)*

Hầu hết các môi trường doanh nghiệp đều sử dụng network share (thư mục chia sẻ mạng) để nhân viên lưu trữ và chia sẻ file giữa các phòng ban. Mặc dù các thư mục chia sẻ này rất cần thiết, chúng vô tình có thể trở thành "mỏ vàng" cho kẻ tấn công, đặc biệt khi các dữ liệu nhạy cảm như thông tin đăng nhập dạng plaintext hoặc file cấu hình bị bỏ quên ở đó. Trong phần này, chúng ta sẽ tìm hiểu cách săn lùng thông tin đăng nhập trên các network share từ cả hệ thống Windows và Linux, sử dụng các công cụ phổ biến, cùng với các kỹ thuật chung mà kẻ tấn công dùng để phát hiện những bí mật bị ẩn giấu.

## Các mẫu (pattern) thông tin đăng nhập phổ biến

Trước khi đi sâu vào các công cụ chuyên dụng, điều quan trọng là phải hiểu các loại mẫu và định dạng file thường tiết lộ thông tin nhạy cảm. Nội dung này đã được đề cập ở các phần trước, nên ở đây sẽ không nhắc lại chi tiết. Tuy nhiên, dưới đây là một vài lưu ý nhanh:

- Tìm các từ khóa trong file như `passw`, `user`, `token`, `key`, và `secret`.
- Tìm các file có phần mở rộng thường liên quan đến việc lưu trữ thông tin đăng nhập, chẳng hạn `.ini`, `.cfg`, `.env`, `.xlsx`, `.ps1`, và `.bat`.
- Chú ý các file có tên "đáng ngờ" chứa các từ như `config`, `user`, `passw`, `cred`, hoặc `initial`.
- Nếu bạn đang cố tìm thông tin đăng nhập trong domain `INLANEFREIGHT.LOCAL`, việc tìm các file chứa chuỗi `INLANEFREIGHT\` có thể sẽ hữu ích.
- Từ khóa cần được bản địa hóa theo mục tiêu tấn công; nếu bạn đang tấn công một công ty Đức, khả năng cao họ sẽ dùng từ "Benutzer" thay vì "User".
- Hãy chú ý đến các share mà bạn đang xem xét, và có chiến lược rõ ràng. Nếu bạn quét mười share, mỗi share có hàng nghìn file, việc này sẽ tốn rất nhiều thời gian. Các share được sử dụng bởi **nhân viên IT** có thể là mục tiêu giá trị hơn so với các share chứa ảnh của công ty.

Với những lưu ý trên, bạn có thể bắt đầu bằng các lệnh tìm kiếm cơ bản trên command-line (ví dụ: `Get-ChildItem -Recurse -Include *.ext \\Server\Share | Select-String -Pattern ...`) trước khi mở rộng sang các công cụ nâng cao hơn. Hãy cùng xem cách sử dụng **MANSPIDER**, **Snaffler**, **SnafflePy**, và **NetExec** để tự động hóa và nâng cao quy trình săn lùng thông tin đăng nhập này.

## Săn lùng từ Windows

### Snaffler
https://github.com/SnaffCon/Snaffler

Công cụ đầu tiên chúng ta sẽ tìm hiểu là **Snaffler**. Đây là một chương trình viết bằng C# mà khi chạy trên một máy đã join vào domain (`domain-joined`), sẽ tự động xác định các network share có thể truy cập được và tìm kiếm các file "đáng chú ý". File `README` trong repository Github mô tả rất chi tiết về các tùy chọn cấu hình, tuy nhiên một lượt quét cơ bản có thể thực hiện như sau:

```cmd
c:\Users\Public>Snaffler.exe -s

 .::::::.:::. :::. :::.  .-:::::'.-:::::'::: .,:::::: :::::::..
 ;;;` ``;;;;, `;;; ;;`;; ;;;'''' ;;;'''' ;;;   ;;;;'''' ;;;;``;;;;
 '[==/[[[[, [[[[[. '[[ ,[[ '[[, [[[,,== [[[,,== [[[   [[cccc   [[[,/[[['
   '''    $ $$$  'Y$c$$c$$$cc$$$c`$$$'`` `$$$'``  $$'   $$""    $$$$$$c
  88b    dP 888    Y88 888    888,888    888     o88oo,.__888oo,__  888b   '88bo,
   'YMmMY'   MMM     YM  YMM    ''`  'MM,   'MM,   ''''YUMMM''''YUMMMMMMM  'W'

                         by l0ss and Sh3r4 - github.com/SnaffCon/Snaffler

[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:42Z [Info] Parsing args...
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Parsed args successfully.
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Invoking DFS Discovery because no ComputerTargets or PathTargets were specified
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Getting DFS paths from AD.
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Found 0 DFS Shares in 0 namespaces.
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Invoking full domain computer discovery.
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Getting computers from AD.
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Got 1 computers from AD.
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Starting to look for readable shares...
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Info] Created all sharefinder tasks.
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Black} <\\DC01.inlanefreight.local\ADMIN$>()
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green} <\\DC01.inlanefreight.local\ADMIN$>(R) Remote Admin
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Black} <\\DC01.inlanefreight.local\C$>()
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green} <\\DC01.inlanefreight.local\C$>(R) Default share
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green} <\\DC01.inlanefreight.local\Company>(R)
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green} <\\DC01.inlanefreight.local\Finance>(R)
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green} <\\DC01.inlanefreight.local\HR>(R)
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green} <\\DC01.inlanefreight.local\IT>(R)
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green} <\\DC01.inlanefreight.local\Marketing>(R)
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green} <\\DC01.inlanefreight.local\NETLOGON>(R) Logon server share
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green} <\\DC01.inlanefreight.local\Sales>(R)
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:43Z [Share] {Green} <\\DC01.inlanefreight.local\SYSVOL>(R) Logon server share
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:51Z [File] {Red} <KeepPassOrKeyInCode|R|passw?o?r?d?>\s*[^\s<]+\s*<|2.3kB|2025-05-01 05:22:48Z>(\\DC01.inlanefreight.local\ADMIN$\Panther\unattend.xml) 5"\ language="neutral"\ versionScope="nonSxS"\ xmlns:wcm="http://schemas\.microsoft\.com/WMIConfig/2002/State"\ xmlns:xsi="http://www\.w3\.org/2001/XMLSchema-instance">\n\t\t\ \ <UserAccounts>\n\t\t\ \ \ \ <AdministratorPassword>\*SENSITIVE\*DATA\*DELETED\* </AdministratorPassword>\n\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ </UserAccounts>\n\ \ \ \ \ \ \ \ \ \ \ \ <OOBE>\n\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ <HideEULAPage>true</HideEULAPage>\n\ \ \ \ \ \ \ \ \ \ \ \ </OOBE>\n\ \ \ \ \ \ \ \ </component
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:53Z [File] {Yellow} <KeepDeployImageByExtension|R|^\.wim$|29.2MB|2022-02-25 16:36:53Z>(\\DC01.inlanefreight.local\ADMIN$\Containers\serviced\WindowsDefenderAppl.wim
[INLANEFREIGHT\jbader@DC01] 2025-05-01 17:41:58Z [File] {Red} <KeepPassOrKeyInCode|R|passw?o?r?d?>\s*[^\s<]+\s*<|2.3kB|2025-05-01 05:22:48Z>(\\DC01.inlanefreight.local\C$\Windows\Panther\unattend.xml) 5"\ language="neutral"\ versionScope="nonSxS"\ xmlns:wcm="http://schemas\.microsoft\.com/WMIConfig/2002/State"\ xmlns:xsi="http://www\.w3\.org/2001/XMLSchema-instance">\n\t\t\ \ <UserAccounts>\n\t\t\ \ \ \ <AdministratorPassword>\*SENSITIVE\*DATA\*DELETED\* </AdministratorPassword>\n\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ </UserAccounts>\n\ \ \ \ \ \ \ \ \ \ \ \ <OOBE>\n\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ <HideEULAPage>true</HideEULAPage>\n\ \ \ \ \ \ \ \ \ \ \ \ </OOBE>\n\ \ \ \ \ \ \ \ </component
<SNIP>
```

Tất cả các công cụ được đề cập trong phần này đều trả về một lượng thông tin rất lớn. Mặc dù chúng hỗ trợ tự động hóa, vẫn cần một lượng đáng kể công sức rà soát thủ công, vì nhiều kết quả khớp có thể là **"false positive" (dương tính giả)**. Hai tham số hữu ích có thể giúp tinh chỉnh quá trình tìm kiếm của Snaffler là:

- `-u` lấy danh sách người dùng từ Active Directory và tìm các tham chiếu đến họ trong các file
- `-i` và `-n` cho phép bạn chỉ định những share nào nên được đưa vào quá trình tìm kiếm

### PowerHuntShares
https://github.com/NetSPI/PowerHuntShares

Một công cụ khác có thể sử dụng là **PowerHuntShares**, một script PowerShell không nhất thiết phải chạy trên một máy đã join domain. Một trong những tính năng hữu ích nhất của nó là tạo ra một **báo cáo HTML** sau khi hoàn tất, cung cấp một giao diện dễ sử dụng để rà soát kết quả:

![Báo cáo tổng hợp PowerHuntShares](images/powerhuntshares-report.png)

*Báo cáo Summary Report của PowerHuntShares: quá trình kiểm thử được thực hiện trong domain inlanefreight.local, phát hiện 5 lỗi mức nghiêm trọng (Critical), 0 mức cao (High), 0 mức trung bình (Medium) và 2 mức thấp (Low) liên quan đến cấu hình ACE (Access Control Entry) trên 4 share, thuộc 1 máy tính trong domain. Tổng cộng có 21 file "đáng chú ý" mà mọi người dùng trong domain đều có thể truy cập, có nguy cơ dẫn đến truy cập dữ liệu trái phép hoặc thực thi mã từ xa. Các share bị ảnh hưởng có 2 file có thể chứa mật khẩu và 2 file có thể chứa dữ liệu nhạy cảm. 0 thông tin đăng nhập được khôi phục trong số 2 file bí mật (secrets) được phát hiện.*

Chúng ta có thể chạy một lượt quét cơ bản bằng **PowerHuntShares** như sau:

```powershell
PS C:\Users\Public\PowerHuntShares> Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public

===============================================================
INVOKE-HUNTSMBSHARES
===============================================================
 Function này tự động thực hiện các tác vụ sau:

 o Xác định domain hiện tại của máy tính
 o Liệt kê các máy tính trong domain
 o Kiểm tra xem các máy tính có phản hồi ping hay không
 o Lọc ra các máy tính có mở cổng TCP 445
 o Liệt kê các SMB share
 o Liệt kê quyền (permission) của các SMB share
 o Xác định các share có thể có quyền truy cập quá mức (excessive privileges)
 o Xác định các share cho phép truy cập đọc (read) hoặc ghi (write)
 o Xác định các share có mức rủi ro cao
 o Xác định chủ sở hữu (owner), tên và cấu trúc thư mục phổ biến của các share
 o Tạo dòng thời gian (timeline) về thời điểm ghi và truy cập gần nhất
 o Tạo báo cáo tổng hợp HTML và các file CSV chi tiết

 Lưu ý: Việc này có thể mất hàng giờ để chạy trong các môi trường lớn.
---------------------------------------------------------------
|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
---------------------------------------------------------------
SHARE DISCOVERY
---------------------------------------------------------------
[*][05/01/2025 12:51] Scan Start
[*][05/01/2025 12:51] Output Directory: c:\Users\Public\SmbShareHunt05012025125123
[*][05/01/2025 12:51] Successful connection to domain controller: DC01.inlanefreight.local
[*][05/01/2025 12:51] Performing LDAP query for computers associated with the inlanefreight.local domain
[*][05/01/2025 12:51] - computers found
[*][05/01/2025 12:51] - 0 subnets found
[*][05/01/2025 12:51] Pinging computers
[*][05/01/2025 12:51] - computers responded to ping requests.
[*][05/01/2025 12:51] Checking if TCP Port 445 is open on computers
[*][05/01/2025 12:51] - 1 computers have TCP port 445 open.
[*][05/01/2025 12:51] Getting a list of SMB shares from 1 computers
[*][05/01/2025 12:51] - 11 SMB shares were found.
[*][05/01/2025 12:51] Getting share permissions from 11 SMB shares
<SNIP>
```

## Săn lùng từ Linux

### MANSPIDER
https://github.com/blacklanternsecurity/MANSPIDER

Nếu bạn không có quyền truy cập vào một máy tính đã join domain, hoặc đơn giản là muốn tìm kiếm file từ xa, các công cụ như **MANSPIDER** cho phép bạn quét các SMB share từ Linux. Cách tốt nhất là chạy **MANSPIDER** thông qua Docker container chính thức để tránh các vấn đề về dependency. Cũng giống như các công cụ khác, **MANSPIDER** cung cấp nhiều tham số có thể cấu hình để tinh chỉnh việc tìm kiếm. Một lượt quét cơ bản tìm các file chứa chuỗi `passw` có thể chạy như sau:

```shellsession
naruto3co@htb[/htb]$ docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider 10.129.234.121 -c 'passw' -u 'mendres' -p 'Inlanefreight2025!'

[+] MANSPIDER command executed: /usr/local/bin/manspider 10.129.234.121 -c passw -u mendres -p Inlanefreight2025!
[+] Skipping files larger than 10.00MB
[+] Using 5 threads
[+] Searching by file content: "passw"
[+] Matching files will be downloaded to /root/.manspider/loot
[+] 10.129.234.121: Successful login as "mendres"
[+] 10.129.234.121: Successful login as "mendres"
<SNIP>
```

### NetExec

Bên cạnh nhiều công dụng khác, **NetExec** cũng có thể được dùng để tìm kiếm qua các network share bằng tùy chọn `--spider`. Chức năng này được mô tả rất chi tiết trên **wiki chính thức**. Một lượt quét cơ bản các network share tìm file chứa chuỗi `"passw"` có thể chạy như sau:

```shellsession
naruto3co@htb[/htb]$ nxc smb 10.129.234.121 -u mendres -p 'Inlanefreight2025!' --spider IT --content --pattern "passw"

SMB         10.129.234.121  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:inlanefreight.local) (signing:True) (SMBv1:False)
SMB         10.129.234.121  445    DC01             [+] inlanefreight.local\mendres:Inlanefreight2025! 
SMB         10.129.234.121  445    DC01             [*] Started spidering
SMB         10.129.234.121  445    DC01             [*] Spidering .
<SNIP>
```

## Bài tập thực hành

Sử dụng thông tin đăng nhập `mendres:Inlanefreight2025!` để kết nối tới máy mục tiêu qua RDP hoặc WinRM, sau đó sử dụng các công cụ và kỹ thuật đã học trong phần này để trả lời các câu hỏi bên dưới. Để thuận tiện, **Snaffler** và **PowerHuntShares** đã được đặt sẵn trong `C:\Users\Public`.

> ⚠️ Trả lời câu hỏi bằng tiếng Anh để đảm bảo hệ thống chấm điểm chính xác.

**Câu hỏi 1** *(+40 XP)*
Một trong các share mà mendres có quyền truy cập chứa thông tin đăng nhập hợp lệ của một người dùng domain khác. Mật khẩu của người dùng đó là gì?

**Câu hỏi 2** *(+40 XP)*
Với vai trò người dùng này, hãy tìm kiếm qua các share khác mà họ có quyền truy cập và xác định mật khẩu của một tài khoản domain admin. Mật khẩu đó là gì?

---

*Nguồn: Hack The Box Academy — Module "Credential Hunting in Network Shares" (Section 19/26)*
