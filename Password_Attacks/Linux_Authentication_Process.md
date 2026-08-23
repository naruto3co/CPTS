# Quy trình xác thực trên Linux (Linux Authentication Process)

*Hack The Box Academy — Section 16/26*


Các bản phân phối Linux hỗ trợ nhiều cơ chế xác thực khác nhau. Một trong những cơ chế phổ biến nhất là **Pluggable Authentication Modules (PAM)**. Các module chịu trách nhiệm cho chức năng này, ví dụ như `pam_unix.so` hoặc `pam_unix2.so`, thường được đặt tại `/usr/lib/x86_64-linux-gnu/security/` trên các hệ thống dựa trên Debian. Các module này quản lý thông tin người dùng, xác thực (authentication), phiên làm việc (session) và việc đổi mật khẩu. Ví dụ, khi người dùng đổi mật khẩu bằng lệnh `passwd`, PAM sẽ được gọi để xử lý và lưu trữ thông tin một cách phù hợp.

Module `pam_unix.so` sử dụng các lời gọi API chuẩn từ các thư viện hệ thống để cập nhật thông tin tài khoản. Hai file chính mà nó đọc/ghi là `/etc/passwd` và `/etc/shadow`. PAM còn bao gồm nhiều module dịch vụ khác, chẳng hạn cho LDAP, mount, và xác thực Kerberos.

## File Passwd

File `/etc/passwd` chứa thông tin về mọi người dùng trên hệ thống và **có thể đọc được bởi tất cả người dùng và dịch vụ**. Mỗi dòng trong file tương ứng với một người dùng và gồm **bảy trường (seven fields)**, lưu dữ liệu liên quan đến người dùng theo định dạng có cấu trúc. Các trường này được phân tách bằng dấu hai chấm (`:`). Một dòng điển hình có dạng như sau:

```shellsession
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```


| Trường (Field) | Giá trị (Value) |
|---|---|
| Username (Tên người dùng) | `htb-student` |
| Password (Mật khẩu) | `x` |
| User ID | `1000` |
| Group ID | `1000` |
| GECOS | `,,,` |
| Home directory (Thư mục home) | `/home/htb-student` |
| Default shell (Shell mặc định) | `/bin/bash` |

Trường quan trọng nhất đối với mục đích của chúng ta là trường **Password**, vì nó có thể chứa nhiều loại giá trị khác nhau. Trong một số trường hợp hiếm (thường trên các hệ thống rất cũ), trường này có thể chứa **chính hash mật khẩu**. Trên các hệ thống hiện đại, hash mật khẩu được lưu trong file `/etc/shadow`, sẽ được xem xét sau. Dù vậy, file `/etc/passwd` vẫn có thể đọc được bởi tất cả (world-readable), nên nếu hash được lưu ở đây, kẻ tấn công hoàn toàn có thể crack được mật khẩu.

Thông thường, trường này sẽ có giá trị `x`, cho biết mật khẩu được lưu dưới dạng hash trong file `/etc/shadow`. Tuy nhiên, cũng có thể xảy ra trường hợp file `/etc/passwd` bị gán nhầm quyền ghi (writeable). Điều này cho phép ta xóa hoàn toàn trường mật khẩu của user `root`.

```shellsession
naruto3co@htb[/htb]$ head -n 1 /etc/passwd
root::0:0:root:/root:/bin/bash
```

Kết quả là khi đăng nhập bằng `root`, hệ thống sẽ **không hiển thị prompt yêu cầu mật khẩu**.

```shellsession
naruto3co@htb[/htb]$ su
root@htb[/htb]#
```

Mặc dù các tình huống trên khá hiếm gặp, chúng ta vẫn nên chú ý và theo dõi các lỗ hổng bảo mật tiềm ẩn, vì có những ứng dụng yêu cầu quyền đặc biệt cho toàn bộ thư mục. Nếu quản trị viên ít kinh nghiệm với Linux (hoặc với các ứng dụng và dependency của chúng), họ có thể vô tình cấp quyền ghi cho thư mục `/etc` và quên khắc phục sau đó.

## File Shadow


Vì việc đọc được giá trị hash mật khẩu có thể gây rủi ro cho toàn bộ hệ thống, file `/etc/shadow` đã được tạo ra. File này có định dạng tương tự `/etc/passwd` nhưng chỉ chịu trách nhiệm lưu trữ và quản lý mật khẩu. Nó chứa toàn bộ thông tin mật khẩu của các user đã tạo. Ví dụ, nếu một user có trong `/etc/passwd` nhưng không có dòng tương ứng trong `/etc/shadow`, user đó được coi là **không hợp lệ (invalid)**. File `/etc/shadow` cũng chỉ có thể đọc được bởi người dùng có quyền quản trị. Định dạng file này gồm **chín trường (nine fields)**:

```shellsession
htb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
```

| Trường (Field) | Giá trị (Value) |
|---|---|
| Username | `htb-student` |
| Password | `$y$j9T$3QSBB6CbHEu...SNIP...f8Ms` |
| Last change (Lần đổi gần nhất) | `18955` |


| Trường (Field) | Giá trị (Value) |
|---|---|
| Min age (Tuổi tối thiểu) | `0` |
| Max age (Tuổi tối đa) | `99999` |
| Warning period (Thời gian cảnh báo) | `7` |
| Inactivity period (Thời gian không hoạt động) | `-` |
| Expiration date (Ngày hết hạn) | `-` |
| Reserved field (Trường dự trữ) | `-` |

Nếu trường Password chứa một ký tự như `!` hoặc `*`, người dùng **không thể đăng nhập bằng mật khẩu Unix**. Tuy nhiên, các phương thức xác thực khác — như Kerberos hay xác thực bằng khóa (key-based authentication) — vẫn có thể được sử dụng. Điều tương tự cũng áp dụng nếu trường Password để trống, nghĩa là không cần mật khẩu để đăng nhập. Điều này có thể khiến một số chương trình từ chối quyền truy cập vào các chức năng nhất định. Trường Password còn tuân theo một định dạng riêng, từ đó ta có thể trích xuất thêm thông tin:

```
$<id>$<salt>$<hashed>
```

Như ta thấy, mật khẩu đã hash được chia thành ba phần. Giá trị **ID** cho biết thuật toán hash mật mã nào đã được sử dụng, thường là một trong các loại sau:

| ID | Thuật toán hash mật mã (Cryptographic Hash Algorithm) |
|---|---|
| `1` | MD5 |
| `2a` | Blowfish |
| `5` | SHA-256 |


| ID | Thuật toán hash mật mã (Cryptographic Hash Algorithm) |
|---|---|
| `6` | SHA-512 |
| `sha1` | SHA1crypt |
| `y` | Yescrypt |
| `gy` | Gost-yescrypt |
| `7` | Scrypt |

Nhiều bản phân phối Linux, bao gồm cả Debian, hiện nay dùng **yescrypt** làm thuật toán hash mặc định. Tuy nhiên, trên các hệ thống cũ hơn, ta vẫn có thể gặp các phương thức hash khác có khả năng bị crack. Quy trình crack sẽ được đề cập ngay sau đây.

## Opasswd

Thư viện PAM (`pam_unix.so`) có thể ngăn người dùng tái sử dụng mật khẩu cũ. Các mật khẩu cũ này được lưu trong file `/etc/security/opasswd`. Cần có quyền quản trị (root) để đọc file này, với điều kiện quyền truy cập chưa bị chỉnh sửa thủ công.

```shellsession
naruto3co@htb[/htb]$ sudo cat /etc/security/opasswd
cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh
```


Nhìn vào nội dung file, ta thấy nó chứa nhiều dòng cho user `cry0l1t3`, được phân tách bằng dấu phẩy (`,`). Một chi tiết quan trọng cần chú ý là **loại hash** đã được sử dụng. Điều này quan trọng vì thuật toán **MD5** (`$1$`) dễ crack hơn đáng kể so với SHA-512. Điều này đặc biệt hữu ích khi xác định các mật khẩu cũ và nhận diện các mẫu lặp lại, vì người dùng thường tái sử dụng các mật khẩu tương tự nhau giữa nhiều dịch vụ hoặc ứng dụng. Việc nhận ra các mẫu này có thể cải thiện đáng kể khả năng đoán đúng mật khẩu.

## Crack thông tin đăng nhập trên Linux (Cracking Linux Credentials)

Khi đã có quyền root trên máy Linux, ta có thể thu thập hash mật khẩu của người dùng và thử crack chúng bằng nhiều phương pháp khác nhau để khôi phục mật khẩu dạng plaintext. Để làm việc này, ta có thể dùng công cụ **unshadow**, được tích hợp sẵn trong John the Ripper (JtR). Công cụ này hoạt động bằng cách kết hợp hai file `passwd` và `shadow` thành một file duy nhất phù hợp để crack.

```shellsession
naruto3co@htb[/htb]$ sudo cp /etc/passwd /tmp/passwd.bak 
naruto3co@htb[/htb]$ sudo cp /etc/shadow /tmp/shadow.bak 
naruto3co@htb[/htb]$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

File "unshadowed" này giờ có thể bị tấn công bằng JtR hoặc hashcat.

```shellsession
naruto3co@htb[/htb]$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

> **Lưu ý:** Đây chính xác là tình huống mà **single crack mode** của JtR được thiết kế để xử lý.

## Đọc thêm

Để tìm hiểu thêm về quy trình xác thực trên Linux, tài liệu này của The Linux Documentation Project là một nguồn tham khảo tốt.


---

## Câu hỏi (Questions)

**Câu hỏi 1 (+40 XP):** Tải file ZIP đính kèm (`linux-authentication-process.zip`) và sử dụng single crack mode để tìm mật khẩu của `martin`. Đó là gì?

**Câu hỏi 2 (+40 XP):** Sử dụng phương pháp wordlist attack để tìm mật khẩu của `sarah`. Đó là gì?
