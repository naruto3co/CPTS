# Truy tìm thông tin đăng nhập trong lưu lượng mạng
*(Credential Hunting in Network Traffic — Hack The Box Academy)*

Trong thế giới bảo mật ngày nay, hầu hết các ứng dụng đều sử dụng TLS để mã hóa dữ liệu nhạy cảm khi truyền tải. Tuy nhiên, không phải môi trường nào cũng được bảo mật đầy đủ. Các hệ thống cũ (legacy), dịch vụ cấu hình sai, hoặc các ứng dụng thử nghiệm được triển khai mà không có HTTPS vẫn có thể dẫn đến việc sử dụng các giao thức không mã hóa như HTTP hoặc SNMP. Những lỗ hổng này tạo ra cơ hội quý giá cho kẻ tấn công: khả năng **truy tìm thông tin đăng nhập ở dạng văn bản thuần (cleartext)** trong lưu lượng mạng. Trong phần này, chúng ta sẽ tìm hiểu các kỹ thuật thực tế để phát hiện thông tin bị lộ, chẳng hạn như tên người dùng và mật khẩu, trong các giao thức plaintext phổ biến bằng Wireshark. Chúng ta cũng sẽ tìm hiểu sơ lược về Pcredz — một công cụ có thể quét nhanh lưu lượng mạng để tìm các dữ liệu này.

Bảng dưới đây liệt kê một số giao thức không mã hóa phổ biến cùng với phiên bản mã hóa tương ứng. Mặc dù ngày nay các phiên bản bảo mật đã trở nên phổ biến hơn, nhưng đã từng có thời điểm các giao thức plaintext được sử dụng rộng rãi.

| Giao thức không mã hóa | Phiên bản mã hóa tương ứng | Mô tả |
|---|---|---|
| HTTP | HTTPS | Dùng để truyền tải các trang web và tài nguyên qua Internet. |
| FTP | FTPS/SFTP | Dùng để truyền file giữa client và server. |
| SNMP | SNMPv3 (có mã hóa) | Dùng để giám sát và quản lý các thiết bị mạng như router, switch. |
| POP3 | POP3S | Lấy email từ mail server về client cục bộ. |
| IMAP | IMAPS | Truy cập và quản lý email trực tiếp trên mail server. |
| SMTP | SMTPS | Gửi email từ client đến server hoặc giữa các mail server với nhau. |
| LDAP | LDAPS | Truy vấn và chỉnh sửa các dịch vụ thư mục như thông tin đăng nhập, vai trò người dùng. |
| RDP | RDP (có TLS) | Cung cấp truy cập máy tính từ xa (Remote Desktop) cho hệ thống Windows. |
| DNS (truyền thống) | DNS over HTTPS (DoH) | Phân giải tên miền thành địa chỉ IP. |
| SMB | SMB over TLS (SMB 3.0) | Chia sẻ file, máy in, và các tài nguyên khác qua mạng. |
| VNC | VNC with TLS/SSL | Cho phép điều khiển đồ họa từ xa một máy tính khác. |

## Wireshark

Wireshark là một công cụ phân tích gói tin (packet analyzer) nổi tiếng, được cài đặt sẵn trong hầu hết các bản phân phối Linux dùng cho pentest. Nó có bộ máy lọc (filter) mạnh mẽ, cho phép tìm kiếm hiệu quả trong cả lưu lượng mạng trực tiếp (live) lẫn đã ghi lại (capture). Một số bộ lọc cơ bản nhưng hữu ích bao gồm:

| Bộ lọc Wireshark | Mô tả |
|---|---|
| `ip.addr == 56.48.210.13` | Lọc các gói tin có địa chỉ IP cụ thể. |
| `tcp.port == 80` | Lọc gói tin theo cổng (ở đây là cổng HTTP). |
| `http` | Lọc lưu lượng HTTP. |
| `dns` | Lọc lưu lượng DNS, hữu ích để theo dõi việc phân giải tên miền. |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Lọc các gói SYN (dùng trong bắt tay TCP - handshake), hữu ích để phát hiện quét cổng hoặc các nỗ lực kết nối. |
| `icmp` | Lọc các gói ICMP (dùng cho Ping), hữu ích cho việc trinh sát (recon) hoặc xử lý sự cố mạng. |
| `http.request.method == "POST"` | Lọc các yêu cầu HTTP POST. Trường hợp các request POST được gửi qua HTTP không mã hóa, rất có thể chúng chứa mật khẩu hoặc thông tin nhạy cảm khác. |
| `tcp.stream eq 53` | Lọc theo một luồng TCP (TCP stream) cụ thể. Giúp theo dõi một cuộc trao đổi giữa hai host. |
| `eth.addr == 00:11:22:33:44:55` | Lọc các gói tin đến/đi từ một địa chỉ MAC cụ thể. |
| `ip.src == 192.168.24.3 && ip.dst == 56.48.210.3` | Lọc lưu lượng giữa hai địa chỉ IP cụ thể. Giúp theo dõi việc giao tiếp giữa các host cụ thể. |

Ví dụ, trong hình bên dưới, chúng ta đang lọc lưu lượng HTTP không mã hóa:

<img width="1325" height="361" alt="image" src="https://github.com/user-attachments/assets/0f4dfe4e-4430-49a7-a361-d32bf51fd61c" />


Trong Wireshark, ta có thể tìm các gói tin chứa byte hoặc chuỗi ký tự cụ thể. Một cách để làm điều này là sử dụng bộ lọc hiển thị như `http contains "passw"`. Ngoài ra, bạn có thể vào **Edit > Find Packet** và nhập chuỗi tìm kiếm mong muốn theo cách thủ công. Ví dụ, bạn có thể tìm các gói tin chứa chuỗi `"passw"`:

<img width="956" height="599" alt="image" src="https://github.com/user-attachments/assets/111c822a-6629-485f-bfd8-16b542077dd5" />

Rất đáng để làm quen với cú pháp bộ lọc của Wireshark, đặc biệt nếu bạn cần thực hiện phân tích lưu lượng mạng sau này.

## Pcredz

**Pcredz** là công cụ dùng để trích xuất thông tin đăng nhập từ lưu lượng mạng trực tiếp hoặc từ file ghi lại gói tin (packet capture). Cụ thể, nó hỗ trợ trích xuất các loại thông tin sau:

- Số thẻ tín dụng
- Thông tin đăng nhập POP
- Thông tin đăng nhập SMTP
- Thông tin đăng nhập IMAP
- Chuỗi cộng đồng (community string) của SNMP
- Thông tin đăng nhập FTP
- Thông tin đăng nhập từ header HTTP NTLM/Basic, cũng như từ HTTP Forms
- Hash NTLMv1/v2 từ nhiều loại lưu lượng khác nhau bao gồm DCE-RPC, SMBv1/2, LDAP, MSSQL, và HTTP
- Hash Kerberos (AS-REQ Pre-Auth etype 23)

Để chạy Pcredz, bạn có thể clone repository và cài đặt tất cả các phụ thuộc (dependencies), hoặc sử dụng Docker container được cung cấp — chi tiết ở phần Install trong file README.

Lệnh sau có thể dùng để chạy Pcredz với một file packet capture:

```shellsession
naruto3co@htb[/htb]$ ./Pcredz -f demo.pcapng -t -v

Pcredz 2.0.2
Author: Laurent Gaffie
Please send bugs/comments/pcaps to: laurent.gaffie@gmail.com
This script will extract NTLM (HTTP,LDAP,SMB,MSSQL,RPC, etc), Kerberos,
FTP, HTTP Basic and credit card data from a given pcap file or from a
live interface.

CC number scanning activated

Unknown format, trying TCPDump format

[1746131482.601354] protocol: udp 192.168.31.211:59022 >
192.168.31.238:161
Found SNMPv2 Community string: s3cr...SNIP...

[1746131482.601640] protocol: udp 192.168.31.211:59022 >
192.168.31.238:161
Found SNMPv2 Community string: s3cr...SNIP...

<SNIP>

[1746131482.658938] protocol: tcp 192.168.31.243:55707 >
192.168.31.211:21
FTP User: le...SNIP...
FTP Pass: qw...SNIP...

demo.pcapng parsed in: 1.82 seconds (File size 15.5 Mo).
```

## Bài tập thực hành

Tải file đính kèm `credential-hunting-in-network-traffic` và giải nén file `demo.pcapng`, sau đó dùng **Wireshark** hoặc **PCredz** để trả lời các câu hỏi sau.

> ⚠️ **Lưu ý:** Trả lời câu hỏi bằng tiếng Anh trên hệ thống HTB Academy để đảm bảo hệ thống chấm chính xác.

**Câu 1** *(+40 XP)*
File packet capture có chứa thông tin thẻ tín dụng dạng cleartext. Số thẻ đó là gì?

**Câu 2** *(+40 XP)*
Chuỗi cộng đồng SNMPv2 (community string) được sử dụng là gì?

**Câu 3** *(+40 XP)*
Mật khẩu của người dùng đăng nhập vào FTP là gì?

**Câu 4** *(+1, +40 XP)*
Người dùng đã tải file nào qua FTP?

---
*Nguồn: Hack The Box Academy — Module 147, Section 3715*
