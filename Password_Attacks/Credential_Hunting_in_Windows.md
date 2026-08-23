# Credential Hunting in Windows (Săn tìm Credential trên Windows)

*Section 15 / 26 — Hack The Box Academy*

Khi đã có quyền truy cập vào một máy Windows mục tiêu thông qua GUI hoặc CLI, việc kết hợp credential hunting (săn tìm credential) vào quy trình tấn công có thể mang lại lợi thế đáng kể. Credential hunting là quá trình tìm kiếm chi tiết trên hệ thống file và trong các ứng dụng khác nhau để phát hiện credential (thông tin đăng nhập).

Để hiểu rõ khái niệm này, hãy đặt mình vào một tình huống: chúng ta đã có quyền truy cập vào workstation Windows 10 của một IT admin thông qua RDP.

## Search-centric (Tìm kiếm là trọng tâm)

Nhiều công cụ có sẵn trên Windows có chức năng tìm kiếm. Ngày nay, hầu hết các ứng dụng và hệ điều hành đều tích hợp tính năng tìm kiếm, vì vậy ta có thể tận dụng điều này trong quá trình engagement. Người dùng có thể đã ghi lại mật khẩu của họ ở đâu đó trên hệ thống. Thậm chí có thể tồn tại các credential mặc định trong nhiều loại file khác nhau.

Sẽ là khôn ngoan nếu ta xây dựng chiến lược tìm kiếm credential dựa trên những gì đã biết về cách hệ thống mục tiêu được sử dụng. Trong trường hợp này, ta biết mình đang truy cập vào workstation của một IT admin.

> Một IT admin thường làm những công việc gì hàng ngày, và công việc nào trong số đó có thể cần đến credential?

Ta có thể dùng câu hỏi này để thu hẹp phạm vi tìm kiếm, giảm thiểu việc đoán mò.

### Các từ khóa quan trọng cần tìm kiếm

Dù truy cập bằng GUI hay CLI, ta đều có công cụ để tìm kiếm, nhưng quan trọng không kém là biết chính xác mình đang tìm gì. Dưới đây là một số từ khóa hữu ích giúp phát hiện credential:

- Passwords
- Passphrases
- Keys
- Username
- User account
- Creds
- Users
- Passkeys
- configuration
- dbcredential
- dbpassword
- pwd
- Login
- Credentials

Hãy dùng một vài từ khóa trong số này để tìm kiếm trên workstation của IT admin.

## Các công cụ tìm kiếm

### Windows Search

Với quyền truy cập GUI, nên thử dùng Windows Search để tìm file trên máy mục tiêu bằng các từ khóa nêu trên.

<img width="1020" height="765" alt="image" src="https://github.com/user-attachments/assets/186c3fa3-cda0-485a-9d6b-e48288939d98" />


Theo mặc định, tính năng này sẽ tìm kiếm trong nhiều cài đặt hệ điều hành và trên hệ thống file các file, ứng dụng có chứa từ khóa đã nhập vào ô tìm kiếm.

### LaZagne

https://github.com/AlessandroZ/LaZagne

Ta cũng có thể tận dụng các công cụ bên thứ ba như **LaZagne** để nhanh chóng phát hiện các credential mà trình duyệt web hoặc ứng dụng đã cài đặt có thể lưu trữ một cách không an toàn. LaZagne được cấu thành từ các **module**, mỗi module nhắm vào một loại phần mềm khác nhau khi tìm kiếm mật khẩu. Một số module phổ biến được mô tả trong bảng dưới đây:

| Module | Mô tả |
|---|---|
| browsers | Trích xuất mật khẩu từ nhiều trình duyệt bao gồm Chromium, Firefox, Microsoft Edge và Opera |
| chats | Trích xuất mật khẩu từ các ứng dụng chat bao gồm Skype |
| mails | Tìm kiếm mật khẩu trong hộp thư, bao gồm Outlook và Thunderbird |
| memory | Dump mật khẩu từ bộ nhớ, nhắm vào KeePass và LSASS |
| sysadmin | Trích xuất mật khẩu từ các file cấu hình của các công cụ sysadmin như OpenVPN và WinSCP |
| windows | Trích xuất các credential đặc thù của Windows, nhắm vào LSA secrets, Credential Manager và nhiều hơn nữa |
| wifi | Dump credential WiFi |

> **Lưu ý:** Trình duyệt web là một trong những nơi đáng chú ý nhất để tìm credential, bởi vì nhiều trình duyệt cung cấp tính năng lưu trữ credential tích hợp sẵn. Ở các trình duyệt phổ biến như Google Chrome, Microsoft Edge và Firefox, credential được lưu trữ ở dạng mã hóa. Tuy nhiên, có nhiều công cụ giải mã các cơ sở dữ liệu credential này có thể tìm thấy trên mạng, chẳng hạn như `firefox_decrypt` và `decrypt-chrome-passwords`. LaZagne hỗ trợ **35** trình duyệt khác nhau trên Windows.

Sẽ hữu ích nếu ta giữ sẵn một bản standalone của LaZagne trên attack host để có thể nhanh chóng chuyển sang máy mục tiêu khi cần. `LaZagne.exe` là đủ dùng trong tình huống này. Ta có thể dùng RDP client để copy file sang máy mục tiêu từ attack host. Nếu dùng `xfreerdp`, ta chỉ cần copy và paste vào phiên RDP đã thiết lập.

Sau khi `LaZagne.exe` đã có trên máy mục tiêu, ta có thể mở Command Prompt hoặc PowerShell, di chuyển đến thư mục chứa file đã upload, và chạy lệnh sau:

```cmd
C:\Users\bob\Desktop> start LaZagne.exe all
```

Lệnh này sẽ chạy LaZagne với tất cả các module đi kèm (`all`). Ta có thể thêm tùy chọn `-vv` để theo dõi những gì công cụ đang thực hiện ở phía sau. Sau khi nhấn Enter, một cửa sổ prompt mới sẽ mở ra và hiển thị kết quả.

```
|====================================================================|
|                                                                    |
|                        The LaZagne Project                        |
|                                                                    |
|                          ! BANG BANG !                            |
|                                                                    |
|====================================================================|

########## User: bob ##########

------------------- Winscp passwords -----------------

[+] Password found !!!
URL: 10.129.202.51
Login: admin
Password: SteveisReallyCool123
Port: 22
```

Nếu dùng tùy chọn `-vv`, ta sẽ thấy các nỗ lực thu thập mật khẩu từ toàn bộ phần mềm mà LaZagne hỗ trợ. Ta cũng có thể xem trên trang GitHub, ở mục "supported software" để biết toàn bộ danh sách phần mềm mà LaZagne sẽ cố gắng thu thập credential. Có thể sẽ khá bất ngờ khi thấy việc lấy credential dạng clear text lại dễ dàng đến vậy — phần lớn là do cách nhiều ứng dụng lưu trữ credential không an toàn.

### findstr

Ta cũng có thể dùng `findstr` để tìm kiếm các pattern trên nhiều loại file. Dựa trên các từ khóa phổ biến, ta có thể dùng biến thể của lệnh này để phát hiện credential trên máy mục tiêu Windows:

```cmd
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

## Những điều cần lưu ý thêm

Có hàng ngàn công cụ và từ khóa có thể dùng để săn tìm credential trên hệ điều hành Windows. Việc lựa chọn công cụ/từ khóa nào chủ yếu phụ thuộc vào chức năng của máy tính. Nếu ta truy cập được vào một Windows Server, cách tiếp cận có thể khác so với khi truy cập vào một Windows Desktop. Luôn để ý cách hệ thống đang được sử dụng — điều này sẽ giúp ta biết nên tìm ở đâu.

Đôi khi ta thậm chí có thể tìm thấy credential khi duyệt và liệt kê thư mục trên hệ thống file trong lúc công cụ đang chạy.

Dưới đây là một số vị trí khác cần lưu ý khi săn tìm credential:

- Mật khẩu trong Group Policy trên share SYSVOL
- Mật khẩu trong các script trên share SYSVOL
- Mật khẩu trong các script trên IT share
- Mật khẩu trong file `web.config` trên các máy dev và IT share
- Mật khẩu trong `unattend.xml`
- Mật khẩu trong trường description của user hoặc computer trên AD
- Cơ sở dữ liệu KeePass (nếu có thể đoán hoặc crack được master password)
- Tìm thấy trên hệ thống người dùng và các share
- Các file có tên như `pass.txt`, `passwords.docx`, `passwords.xlsx` tìm thấy trên hệ thống người dùng, các share và SharePoint

---

Bạn đã có quyền truy cập vào workstation Windows 10 của một IT admin và bắt đầu quá trình săn tìm credential bằng cách tìm kiếm ở các vị trí lưu trữ phổ biến.

**Kết nối với mục tiêu và sử dụng những gì đã học để tìm câu trả lời cho các câu hỏi thử thách.**

## Connect to HTB

**Target(s):** Spawn hệ thống mục tiêu để lấy IP và trả lời câu hỏi

*(Nút "Spawn the target system")*

*(Tùy chọn "Enable step-by-step solutions" — PRO)*

> ⚠️ Trả lời câu hỏi bằng tiếng Anh để đảm bảo hệ thống chấm chính xác.

**Câu hỏi 1** (+40 XP)
Bob dùng mật khẩu nào để kết nối SSH vào các Switch? (Định dạng: phân biệt chữ hoa/thường)
*RDP vào với user "Bob" và mật khẩu "HTB_@cademy_stdnt!"*

**Câu hỏi 2** (+40 XP)
Mã truy cập GitLab mà Bob sử dụng là gì? (Định dạng: phân biệt chữ hoa/thường)
*RDP vào với user "Bob" và mật khẩu "HTB_@cademy_stdnt!"*

**Câu hỏi 3** (+40 XP)
Bob dùng credential nào với WinSCP để kết nối vào file server? (Định dạng: username:password, phân biệt chữ hoa/thường)
*RDP vào với user "Bob" và mật khẩu "HTB_@cademy_stdnt!"*

**Câu hỏi 4** (+40 XP)
Mật khẩu mặc định của mọi tài khoản Domain User mới được tạo trong Inlanefreight là gì? (Định dạng: phân biệt chữ hoa/thường)
*RDP vào với user "Bob" và mật khẩu "HTB_@cademy_stdnt!"*

**Câu hỏi 5** (+40 XP, +1)
Credential để truy cập vào Edge-Router là gì? (Định dạng: username:password, phân biệt chữ hoa/thường)
*RDP vào với user "Bob" và mật khẩu "HTB_@cademy_stdnt!"*

---

*Mark Complete & Next*
