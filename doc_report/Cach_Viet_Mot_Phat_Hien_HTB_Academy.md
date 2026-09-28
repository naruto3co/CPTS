# Cách Viết Một Phát Hiện (How to Write Up a Finding) — Hack The Box Academy

Phần Findings (Các Phát Hiện) trong báo cáo của ta chính là "phần thịt" (meat). Đây là nơi ta thể hiện những gì đã tìm được, cách khai thác chúng, và đưa ra hướng dẫn cho khách hàng về cách khắc phục các vấn đề. Càng chi tiết bao nhiêu trong mỗi phát hiện càng tốt bấy nhiêu. Điều này sẽ giúp đội kỹ thuật tự tái hiện được phát hiện và sau đó có thể kiểm tra xem bản vá của họ có hiệu quả hay không. Việc chi tiết trong phần này cũng sẽ giúp ích cho bất kỳ ai được giao nhiệm vụ thực hiện đánh giá sau khắc phục (post-remediation assessment) nếu khách hàng thuê công ty bạn thực hiện việc đó. Dù ta thường có sẵn các phát hiện "mẫu" (stock) trong một cơ sở dữ liệu nào đó, điều cần thiết là phải điều chỉnh chúng cho phù hợp với môi trường cụ thể của khách hàng để đảm bảo không trình bày sai lệch bất cứ điều gì.

## Cấu Trúc Của Một Phát Hiện (Breakdown of a Finding)

Mỗi phát hiện nên có cùng một dạng thông tin chung, được tùy chỉnh theo hoàn cảnh cụ thể của khách hàng. Nếu một phát hiện được viết để phù hợp với nhiều tình huống hoặc giao thức khác nhau, phiên bản cuối cùng nên được điều chỉnh để chỉ tham chiếu đến tình huống cụ thể mà bạn đã xác định. "Default Credentials" (thông tin đăng nhập mặc định) có thể mang ý nghĩa rủi ro khác nhau tùy vào việc nó ảnh hưởng đến một máy in DeskJet hay hệ thống điều khiển HVAC của tòa nhà, hoặc một ứng dụng web có tác động lớn khác. Tối thiểu, các thông tin sau nên được đưa vào mỗi phát hiện:

- Mô tả phát hiện và (các) nền tảng bị ảnh hưởng bởi lỗ hổng
- Tác động nếu phát hiện không được khắc phục
- Các hệ thống, mạng, môi trường hoặc ứng dụng bị ảnh hưởng
- Khuyến nghị về cách xử lý vấn đề
- Các liên kết tham khảo với thông tin bổ sung về phát hiện và cách khắc phục
- Các bước tái hiện vấn đề và bằng chứng bạn đã thu thập được

Một số trường thông tin bổ sung, tùy chọn:
```
- CVE
- OWASP, MITRE IDs
- Điểm CVSS hoặc điểm số tương tự
- Mức độ dễ khai thác và xác suất bị tấn công
- Bất kỳ thông tin nào khác có thể giúp hiểu và giảm thiểu cuộc tấn công
```

## Trình Bày Các Bước Tái Hiện Phát Hiện Một Cách Đầy Đủ

Như đã đề cập ở phần trước về Executive Summary, điều quan trọng cần nhớ là dù người liên hệ chính (point-of-contact) của bạn có thể khá am hiểu kỹ thuật, nếu họ không có nền tảng cụ thể về pentest, khả năng khá cao là họ sẽ không hiểu được mình đang xem gì. Họ có thể chưa từng nghe đến công cụ bạn dùng để khai thác lỗ hổng, càng không hiểu được điều gì là quan trọng trong "bức tường văn bản" mà lệnh đó xuất ra khi chạy. Vì vậy, điều quan trọng là phải tự đề phòng việc mặc định coi mọi thứ là hiển nhiên và cho rằng mọi người tự biết cách điền vào chỗ trống. Nếu không làm đúng điều này, một lần nữa, nó sẽ làm giảm hiệu quả của sản phẩm bàn giao — nhưng lần này là trong mắt đối tượng độc giả kỹ thuật của bạn. Một số khái niệm cần cân nhắc:

- **Tách mỗi bước thành một hình (figure) riêng.** Nếu bạn thực hiện nhiều bước trong cùng một hình, người đọc không quen thuộc với các công cụ đang sử dụng có thể không hiểu chuyện gì đang diễn ra, càng không có ý tưởng về cách tự tái hiện lại.
- **Nếu cần thiết lập cấu hình (ví dụ: các module Metasploit), hãy chụp lại toàn bộ cấu hình** để người đọc thấy được cấu hình exploit trông như thế nào trước khi chạy exploit. Tạo một hình thứ hai thể hiện điều gì xảy ra khi bạn chạy exploit.
- **Viết một đoạn tường thuật (narrative) giữa các hình**, mô tả điều gì đang diễn ra và bạn đang suy nghĩ gì tại thời điểm đó trong quá trình đánh giá. Đừng cố giải thích những gì đang diễn ra trong hình chỉ bằng chú thích (caption), và đừng để một loạt hình liên tiếp nhau mà không có văn bản giải thích xen giữa.
- **Sau khi trình bày demo bằng bộ công cụ ưa thích của bạn, hãy đề xuất các công cụ thay thế** có thể dùng để xác thực phát hiện nếu có (chỉ cần nhắc tên công cụ và cung cấp link tham khảo, không cần thực hiện lại exploit hai lần với nhiều công cụ khác nhau).

Mục tiêu chính của bạn nên là trình bày bằng chứng theo cách dễ hiểu và có thể hành động được đối với khách hàng. Hãy nghĩ về cách khách hàng sẽ sử dụng thông tin bạn trình bày. Nếu bạn đang thể hiện một lỗ hổng trong ứng dụng web, ảnh chụp màn hình Burp không phải là cách tốt nhất để trình bày thông tin này nếu bạn đang tự tạo các web request. Khách hàng có thể sẽ muốn copy/paste payload từ bài kiểm thử của bạn để tái tạo lại, và họ không thể làm điều đó nếu chỉ có ảnh chụp màn hình.

Một điều quan trọng khác cần cân nhắc là liệu bằng chứng của bạn có hoàn toàn và tuyệt đối bảo vệ được (defensible) hay không. Ví dụ, nếu bạn đang cố chứng minh rằng thông tin được truyền dưới dạng cleartext do sử dụng basic authentication trong một ứng dụng web, chỉ chụp màn hình popup đăng nhập là chưa đủ. Điều đó chỉ cho thấy basic auth đang được sử dụng, nhưng không chứng minh được rằng thông tin đang được truyền dưới dạng không mã hóa. Trong trường hợp này, việc hiển thị popup đăng nhập với thông tin đăng nhập giả được nhập vào, cùng với thông tin đăng nhập dạng cleartext trong một bản packet capture bằng Wireshark của request xác thực dễ đọc, sẽ không để lại chỗ nào để tranh cãi. Tương tự, nếu bạn đang cố chứng minh sự tồn tại của một lỗ hổng trong một ứng dụng web cụ thể hoặc thứ gì đó khác có giao diện đồ họa (như RDP), điều quan trọng là phải chụp lại URL trên thanh địa chỉ hoặc output của lệnh `ifconfig` hay `ipconfig` để chứng minh rằng đó là host của khách hàng, chứ không phải một ảnh ngẫu nhiên nào đó tải từ Google. Ngoài ra, nếu bạn chụp màn hình trình duyệt, hãy tắt thanh bookmark và vô hiệu hóa mọi tiện ích mở rộng (extension) trình duyệt thiếu chuyên nghiệp, hoặc dùng riêng một trình duyệt cho công việc kiểm thử.

Dưới đây là ví dụ về cách trình bày các bước lấy hash bằng công cụ Responder và crack offline bằng Hashcat. Dù không hoàn toàn bắt buộc, việc liệt kê các công cụ thay thế như đã làm với phát hiện này có thể là điều tốt. Khách hàng có thể đang làm việc trên máy Windows và thấy một script PowerShell hoặc file thực thi thân thiện hơn với người dùng, hoặc quen thuộc hơn với một bộ công cụ khác. Lưu ý rằng ta cũng đã che (redact) hash và mật khẩu cleartext vì báo cáo này có thể được chuyển qua nhiều đối tượng độc giả khác nhau, nên tốt nhất là nên che thông tin đăng nhập bất cứ khi nào có thể.

**Bằng chứng của phát hiện:**

Chạy công cụ Responder để cố gắng lấy được password hash của tài khoản người dùng.

*(Hình 18: Chạy Responder)*
```
$ sudo responder -I eth0 -wrfv

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
bsmith::INLANEFREIGHT:7ecXXXXXX98ebc:73D1B2XXXXXXXXXXX45085A651:0101000000...
<REDACTED>
```

Crack thành công một password hash bằng Hashcat để tiết lộ giá trị mật khẩu dạng cleartext.

*(Hình 19: Crack Mật Khẩu bằng Hashcat)*
```
$ hashcat -m 5600 bsmith_hash /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

BSMITH::INLANEFREIGHT:7eccd965c4b98ebc:73d1b2c8c5f9861eefd31bb45085a651:01...
<REDACTED>
```
<img width="957" height="979" alt="image" src="https://github.com/user-attachments/assets/8b23c792-6518-47b7-9f28-8ce2b4f5fabe" />

## Các Khuyến Nghị Khắc Phục Hiệu Quả

### Ví dụ 1

**Kém:** *"Cấu hình lại các thiết lập registry để tăng cường bảo mật chống lại X."*

**Tốt:** *"Để khắc phục hoàn toàn phát hiện này, các registry hive sau đây cần được cập nhật với các giá trị chỉ định. Lưu ý rằng các thay đổi đối với các thành phần quan trọng như registry nên được thực hiện thận trọng và thử nghiệm trên một nhóm nhỏ trước khi áp dụng thay đổi trên diện rộng.*
*[liệt kê đường dẫn đầy đủ của các registry hive bị ảnh hưởng]*
*Thay đổi giá trị X thành giá trị Y"*

**Lý do:**

Dù ví dụ "kém" ít nhiều vẫn có ích, nó khá lười biếng, và bạn đang bỏ lỡ một cơ hội học hỏi. Một lần nữa, người đọc báo cáo này có thể không có kinh nghiệm sâu về Windows như bạn, và đưa cho họ một khuyến nghị đòi hỏi hàng giờ để tự tìm ra cách thực hiện chỉ khiến họ thêm bực bội. Hãy làm bài tập của mình và cụ thể nhất có thể một cách hợp lý. Làm như vậy có các lợi ích sau:

- Bạn sẽ học được nhiều hơn qua cách này và sẽ tự tin hơn nhiều khi trả lời câu hỏi trong buổi xem xét báo cáo. Điều này sẽ củng cố sự tin tưởng của khách hàng đối với bạn, và là kiến thức bạn có thể tận dụng cho các đánh giá tương lai cũng như giúp nâng cao trình độ cho đội của mình.
- Khách hàng sẽ đánh giá cao việc bạn đã nghiên cứu thay họ và trình bày cụ thể những gì cần làm để họ có thể thực hiện hiệu quả nhất. Điều này sẽ tăng khả năng họ mời bạn thực hiện các đánh giá trong tương lai và giới thiệu bạn cùng đội của mình cho bạn bè họ.

Cũng đáng chú ý rằng ví dụ "tốt" bao gồm một cảnh báo rằng việc thay đổi thứ gì đó quan trọng như registry mang theo rủi ro riêng và nên được thực hiện thận trọng. Một lần nữa, điều này cho khách hàng thấy rằng bạn đang nghĩ đến lợi ích tốt nhất của họ và thực sự mong muốn họ thành công. Dù muốn hay không, sẽ có những khách hàng làm theo mọi thứ bạn nói một cách mù quáng, và sẽ không ngần ngại quy trách nhiệm cho bạn nếu việc đó làm hỏng thứ gì đó.

### Ví dụ 2

**Kém:** *"Triển khai [một công cụ thương mại nào đó có giá rất đắt] để xử lý phát hiện này."*

**Tốt:** *"Có nhiều cách tiếp cận khác nhau để xử lý phát hiện này. [Tên nhà cung cấp phần mềm bị ảnh hưởng] đã công bố một giải pháp tạm thời (workaround) như một biện pháp xử lý trong lúc chờ đợi. Để ngắn gọn, một liên kết hướng dẫn chi tiết đã được cung cấp trong phần liên kết tham khảo bên dưới. Ngoài ra, có các công cụ thương mại có thể vô hiệu hóa hoàn toàn chức năng dễ bị tấn công trong phần mềm bị ảnh hưởng, nhưng các công cụ này có thể có chi phí quá cao."*

**Lý do:**

Ví dụ "kém" không cho khách hàng cách nào để khắc phục vấn đề mà không phải chi rất nhiều tiền — số tiền mà họ có thể không có. Dù công cụ thương mại có thể là giải pháp dễ dàng nhất, nhiều khách hàng sẽ không có ngân sách để làm vậy và cần một giải pháp thay thế. Giải pháp thay thế đó có thể chỉ là biện pháp tạm bợ (bandaid) hoặc rất cồng kềnh, hoặc cả hai, nhưng ít nhất nó sẽ giúp khách hàng có thêm thời gian cho đến khi nhà cung cấp phát hành bản vá chính thức.

## Chọn Nguồn Tham Khảo Chất Lượng

Mỗi phát hiện nên bao gồm một hoặc nhiều tham chiếu bên ngoài để đọc thêm về một lỗ hổng hoặc cấu hình sai cụ thể. Một số tiêu chí giúp tăng tính hữu ích của một nguồn tham khảo:

- **Một nguồn trung lập, không thiên vị nhà cung cấp (vendor-agnostic)** là hữu ích. Rõ ràng, nếu bạn phát hiện một lỗ hổng trên thiết bị ASA, một link tham khảo từ Cisco là hợp lý, nhưng tôi sẽ không dựa vào nguồn của họ cho bất cứ thứ gì ngoài phạm vi mạng (networking). Nếu bạn tham chiếu một bài viết do chính nhà cung cấp sản phẩm viết, khả năng cao bài viết đó sẽ tập trung nói về việc sản phẩm của họ có thể giúp gì, trong khi tất cả những gì người đọc muốn biết là cách tự khắc phục.
- **Một hướng dẫn hoặc giải thích kỹ lưỡng** về phát hiện cùng bất kỳ giải pháp tạm thời hay biện pháp giảm thiểu nào được khuyến nghị là điều đáng ưu tiên. Đừng chọn các bài viết bị chặn sau paywall hoặc chỉ cho bạn xem một phần thông tin cần thiết nếu không trả phí.
- **Sử dụng các bài viết đi thẳng vào vấn đề nhanh chóng.** Đây không phải trang web công thức nấu ăn, và không ai quan tâm bà bạn đã từng làm những chiếc bánh quy đó bao nhiêu lần. Ta có vấn đề cần giải quyết, và việc bắt ai đó lục tung toàn bộ tài liệu NIST 800-53 hoặc một RFC gây khó chịu nhiều hơn là hữu ích.
- **Chọn các nguồn có website sạch sẽ**, không khiến bạn cảm thấy như có một đám máy đào crypto đang chạy ngầm hoặc quảng cáo hiện lên khắp nơi.
- **Nếu có thể, hãy tự viết một số tài liệu nguồn của riêng bạn và viết blog về nó.** Việc nghiên cứu sẽ giúp bạn giải thích tác động của phát hiện cho khách hàng, và dù cộng đồng infosec khá hữu ích, tốt hơn là không nên dẫn khách hàng của bạn đến website của đối thủ cạnh tranh.

## Ví Dụ Về Các Phát Hiện

Dưới đây là một vài ví dụ về phát hiện. Hai ví dụ đầu là các vấn đề có thể được phát hiện trong một Internal Penetration Test. Như bạn có thể thấy, mỗi phát hiện bao gồm tất cả các thành phần chính: một mô tả chi tiết giải thích chuyện gì đang diễn ra, tác động đến môi trường nếu phát hiện không được khắc phục, các host bị ảnh hưởng bởi vấn đề (hoặc toàn bộ domain), lời khuyên khắc phục mang tính chung chung, không đề xuất công cụ của nhà cung cấp cụ thể, và đưa ra nhiều lựa chọn để khắc phục. Cuối cùng, các link tham khảo đến từ những nguồn uy tín, nổi tiếng, khó có khả năng bị gỡ bỏ trong tương lai gần như một blog cá nhân có thể gặp phải.

*Một lưu ý về định dạng: Đây có thể là một chủ đề gây tranh cãi. Các ví dụ phát hiện ở đây được trình bày theo dạng bảng, nhưng nếu bạn từng làm việc trong Word hoặc thử tự động hóa việc tạo báo cáo, bạn sẽ biết rằng bảng có thể là một cơn ác mộng để xử lý. Vì lý do đó, một số người chọn cách tách các phần trong phát hiện bằng các cấp tiêu đề (heading) khác nhau. Cả hai cách tiếp cận đều chấp nhận được, vì điều quan trọng là thông điệp của bạn có truyền tải được đến người đọc hay không, và việc dễ dàng nhận biết các dấu hiệu trực quan cho biết khi nào một phát hiện kết thúc và phát hiện khác bắt đầu — khả năng đọc hiểu (readability) là quan trọng nhất. Nếu bạn đạt được điều đó, màu sắc, bố cục, thứ tự, và thậm chí tên các phần đều có thể được điều chỉnh.*

### Ví dụ phát hiện: Weak Kerberos Authentication ("Kerberoasting")

**1. Weak Kerberos Authentication ("Kerberoasting") - Mức độ: Cao (High)**

| Trường thông tin | Nội dung |
|---|---|
| **CWE** | CWE-522 |
| **Điểm CVSS 3.1** | 9.5 |
| **Mô tả (bao gồm nguyên nhân gốc rễ)** | Trong môi trường Active Directory (AD), Service Principal Name (SPN) được dùng để định danh duy nhất các instance của một dịch vụ Windows. Xác thực Kerberos yêu cầu mỗi SPN phải được liên kết với một tài khoản dịch vụ (tài khoản người dùng Active Directory). Bất kỳ người dùng AD đã xác thực nào cũng có thể yêu cầu một hoặc nhiều vé Kerberos Ticket-Granting Service (TGS) từ domain controller cho bất kỳ tài khoản SPN nào. Các vé này được mã hóa bằng password hash NTLM của tài khoản AD tương ứng. Chúng có thể bị brute-force offline bằng công cụ crack mật khẩu như Hashcat nếu mật khẩu yếu được sử dụng cùng với thuật toán mã hóa RC4. Nếu mã hóa AES đang được dùng, sẽ cần nhiều tài nguyên hơn để "crack" một vé nhằm lộ ra mật khẩu cleartext của tài khoản, nhưng vẫn có thể thực hiện được nếu mật khẩu yếu đang được sử dụng. |
| **Tác động an ninh** | Một cuộc tấn công Kerberoasting thành công kết hợp với mật khẩu bị crack có thể dẫn đến di chuyển ngang và leo thang đặc quyền trong môi trường AD. Nếu mật khẩu của một tài khoản Domain Administrator hoặc tương đương bị crack, kẻ tấn công có thể kiểm soát hầu hết, nếu không muốn nói là toàn bộ, tài nguyên trong domain. |
| **Domain bị ảnh hưởng** | INLANEFREIGHT.LOCAL |
| **Khắc phục** | Khi có thể, loại bỏ SPN trong môi trường để chuyển sang sử dụng Group Managed Service Accounts (gMSA), vốn không bị ảnh hưởng bởi kiểu tấn công này. Nếu không thể chuyển sang gMSA, các bước sau sẽ giúp giảm thiểu rủi ro của cuộc tấn công này: Bật mã hóa Kerberos AES thay vì RC4; Sử dụng mật khẩu mạnh với 25+ ký tự cho các tài khoản dịch vụ và xoay vòng định kỳ; Giới hạn đặc quyền của các tài khoản dịch vụ và tránh tạo SPN gắn với các tài khoản có đặc quyền cao như Domain Administrator. |
| **Tham khảo bên ngoài** | https://attack.mitre.org/techniques/T1558/003/ |
<img width="883" height="704" alt="image" src="https://github.com/user-attachments/assets/7833ef09-f1e6-4ded-b3db-47d2acc46d43" />

### Ví dụ phát hiện: Tomcat Manager Weak/Default Credentials

**2. Tomcat Manager Weak/Default Credentials - Mức độ: Cao (High)**
<img width="876" height="590" alt="image" src="https://github.com/user-attachments/assets/141f60e5-990b-4eca-a07b-08518b6c0961" />

| Trường thông tin | Nội dung |
|---|---|
| **CWE** | CWE-521 |
| **Điểm CVSS 3.1** | 9.5 |
| **Mô tả (bao gồm nguyên nhân gốc rễ)** | Một server Apache Tomcat được phát hiện đang để lộ URL đăng nhập *Tomcat Manager* và sử dụng thông tin đăng nhập yếu/mặc định để truy cập vào backend *Manager* (admin). |
| **Tác động an ninh** | Kẻ tấn công có được quyền truy cập vào khu vực *Tomcat Manager* có thể tải lên một ứng dụng độc hại thông qua file WAR chứa mã JSP tùy chỉnh. Mã này có thể được dùng để chạy các lệnh tùy ý trên server bên dưới, trong ngữ cảnh của tài khoản dịch vụ mà instance Apache Tomcat đang chạy dưới quyền đó. Instance Tomcat này đang chạy dưới một tài khoản dịch vụ cục bộ được cấp đặc quyền có thể bị lợi dụng để leo thang lên tài khoản NT AUTHORITY\SYSTEM toàn quyền, giành quyền kiểm soát hoàn toàn server, có khả năng lấy được quyền truy cập vào thông tin đăng nhập và các dữ liệu nhạy cảm khác. |
| **(Các) Host bị ảnh hưởng** | 192.168.195.205 (8080/TCP) |
| **Khắc phục** | Giới hạn quyền truy cập vào URL Tomcat Manager chỉ ở localhost hoặc chỉ một số địa chỉ IP chọn lọc nếu URL này cần được truy cập từ xa bởi quản trị viên. Đổi tên tài khoản administrator mặc định thành một tên riêng biệt và đặt mật khẩu ngẫu nhiên, mạnh, không xuất hiện trong bất kỳ wordlist nào, vì trang Tomcat Manager sử dụng Basic Authentication — vốn không có cơ chế bảo vệ nội tại nào chống lại tấn công brute-force mật khẩu. |
| **Tham khảo bên ngoài** | https://attack.mitre.org/techniques/T1078/001/ |

## Phát Hiện Viết Kém (Poorly Written Finding)
<img width="946" height="444" alt="image" src="https://github.com/user-attachments/assets/ff1a6794-d99d-4e6c-9cac-de95e52c48e8" />

Dưới đây là ví dụ về một phát hiện được viết kém, có một số vấn đề:

- Định dạng cẩu thả với đường link CWE
- Không điền điểm CVSS (không bắt buộc, nhưng nếu template báo cáo của bạn có dùng đến, bạn nên điền)
- Phần Description không giải thích rõ ràng vấn đề hoặc nguyên nhân gốc rễ
- Phần tác động an ninh (security impact) mơ hồ và chung chung
- Phần Remediation không rõ ràng và không thể hành động được

Nếu tôi là người đọc báo cáo này, tôi có thể thấy phát hiện này "xấu" (vì nó màu đỏ), nhưng tại sao tôi phải quan tâm? Tôi cần làm gì với nó? Mỗi phát hiện nên trình bày vấn đề một cách chi tiết và giáo dục người đọc về vấn đề đang gặp phải (rất có thể họ chưa từng nghe về Kerberoasting hay một kiểu tấn công nào khác). Cần trình bày rõ ràng rủi ro an ninh và **tại sao** vấn đề này cần được khắc phục, cùng với một số khuyến nghị khắc phục có thể hành động được.
<img width="946" height="444" alt="image" src="https://github.com/user-attachments/assets/a7945067-3064-45aa-84c1-6726c0b32cfa" />

**2. Kerberoasting - Mức độ: Cao (High)**

| Trường thông tin | Nội dung |
|---|---|
| **CWE** | https://cwe.mitre.org/data/definitions/522.html |
| **Điểm CVSS 3.1** | *(để trống)* |
| **Mô tả (bao gồm nguyên nhân gốc rễ)** | Bất kỳ Domain User nào cũng có thể lấy password hash cho các tài khoản Service Principal Name bằng Rubeus hoặc PowerView, sau đó crack chúng để lấy mật khẩu người dùng bằng Hashcat. |
| **Tác động an ninh** | Kerberoasting có thể dẫn đến truy cập trái phép hoặc chiếm quyền Domain Admin. |
| **Domain bị ảnh hưởng** | INLANEFREIGHT.LOCAL |
| **Khắc phục** | Xóa tất cả các tài khoản SPN khỏi domain; Đặt mật khẩu tài khoản SPN dài 25+ ký tự; Sử dụng gMSA thay cho SPN nếu có thể. |
| **Tham khảo bên ngoài** | https://attack.mitre.org/techniques/T1558/003/ |

*(Đây chính là ví dụ về phát hiện viết kém — có thể thấy phần Description quá đơn giản, không giải thích rõ nguyên nhân gốc rễ; phần Security Impact chung chung không giải thích tại sao lại nghiêm trọng; phần Remediation thiếu ngữ cảnh và không hướng dẫn cách thực hiện cụ thể.)*

## Thực Hành (Hands-On Practice)

VM mục tiêu có thể được khởi tạo trong phần này có sẵn một bản sao đang chạy của công cụ viết báo cáo WriteHat, được phát triển bởi Black Lantern Security. Đây là công cụ hữu ích để xây dựng cơ sở dữ liệu các phát hiện và tạo ra các báo cáo tùy chỉnh. Dù ta không xác nhận (endorse) bất kỳ công cụ cụ thể nào trong module này, nhiều công cụ báo cáo có cách hoạt động tương tự nhau, nên việc thử nghiệm với WriteHat sẽ giúp bạn có ý tưởng tốt về cách các công cụ loại này hoạt động. Hãy thực hành thêm các phát hiện vào cơ sở dữ liệu, xây dựng và tạo ra một báo cáo, v.v. Ta đã điền sẵn vào cơ sở dữ liệu phát hiện một số danh mục phát hiện phổ biến, cùng một số phát hiện có trong báo cáo mẫu đính kèm module này. Hãy thử nghiệm thoải mái và luyện tập các kỹ năng được dạy trong phần này. Lưu ý rằng bất kỳ điều gì bạn nhập vào công cụ sẽ không được lưu lại sau khi target hết hạn, nên nếu bạn viết bất kỳ phát hiện thực hành nào, hãy nhớ lưu một bản sao cục bộ. Công cụ này cũng sẽ hữu ích cho bài lab thực hành có hướng dẫn ở cuối module.

Sau khi target được khởi tạo, truy cập vào `https://<IP mục tiêu>` và đăng nhập với thông tin đăng nhập `htb-student:HTB_@cademy_stdnt!`.
<img width="1246" height="655" alt="image" src="https://github.com/user-attachments/assets/e5f4a1b8-6501-454b-b66b-04124af09ffb" />

Hãy luyện tập viết các phát hiện và khám phá công cụ. Bạn thậm chí có thể thấy thích công cụ này đến mức muốn dùng nó như một phần trong quy trình làm việc của mình. Một ý tưởng là cài đặt một bản sao cục bộ và luyện tập viết các phát hiện cho các vấn đề bạn phát hiện được trong các lab của module Academy hoặc các box/lab trên nền tảng chính của HTB.

## Sắp Xong (Nearly There)

Sau khi đã đề cập đến cách giữ tổ chức trong quá trình pentest, các loại báo cáo, các thành phần tiêu chuẩn của một báo cáo, và cách viết một phát hiện, ta có một số mẹo/thủ thuật báo cáo để chia sẻ với bạn từ kinh nghiệm thực tế của chúng tôi trong ngành.

---

*Tài liệu gốc: [How to Write Up a Finding | Hack The Box Academy](https://academy.hackthebox.com/app/module/162/section/1536)*
