# Mẹo và Thủ Thuật Viết Báo Cáo (Reporting Tips and Tricks) — Hack The Box Academy

Báo cáo là một phần thiết yếu của quy trình kiểm thử xâm nhập, nhưng nếu quản lý kém, nó có thể trở nên rất tẻ nhạt và dễ mắc lỗi. Một khía cạnh then chốt của việc làm báo cáo là ta nên xây dựng báo cáo ngay từ đầu. Việc này bắt đầu từ cách tổ chức cấu trúc/thiết lập ghi chú của ta, nhưng cũng có những lúc ta đang chạy một bản quét khám phá (discovery scan) kéo dài, khi đó ta có thể điền các phần đã có template trong báo cáo như thông tin liên hệ, tên khách hàng, phạm vi (scope), v.v. Trong khi kiểm thử, ta có thể viết luôn Attack Chain và từng phát hiện cùng toàn bộ bằng chứng cần thiết, để không phải cuống cuồng chụp lại bằng chứng sau khi đánh giá kết thúc. Làm việc theo kiểu "vừa làm vừa viết" sẽ đảm bảo báo cáo không bị làm vội và không bị trả về từ khâu QA với hàng đống chỉnh sửa màu đỏ.

## Template (Mẫu báo cáo)

Điều này lẽ ra không cần phải nói, nhưng ta không nên "phát minh lại bánh xe" với mỗi báo cáo mình viết. Tốt nhất là có một template báo cáo trống cho mỗi loại đánh giá mà ta thực hiện (thậm chí cả những loại ít gặp!). Nếu ta không dùng công cụ báo cáo mà chỉ làm việc theo kiểu MS Word truyền thống, ta vẫn có thể xây dựng template báo cáo với macro và các placeholder để điền sẵn một số dữ liệu mà ta phải điền cho mọi đánh giá. Ta nên luôn làm việc với template trống mỗi lần, thay vì chỉ chỉnh sửa báo cáo của một khách hàng trước đó, vì như vậy có nguy cơ để sót tên khách hàng khác trong báo cáo hoặc các dữ liệu không khớp với môi trường hiện tại. Kiểu lỗi này khiến ta trông thiếu chuyên nghiệp và hoàn toàn có thể tránh được.

## Mẹo và Thủ Thuật MS Word

Microsoft Word có thể gây khó chịu khi làm việc, nhưng có nhiều cách để ta khiến nó làm việc *cho* mình để cuộc sống dễ dàng hơn, và theo kinh nghiệm của chúng tôi, nó dễ dàng là "cái ác nhỏ nhất" trong số các lựa chọn hiện có. Dưới đây là một vài mẹo và thủ thuật mà chúng tôi đã tích lũy qua nhiều năm trên con đường trở thành "guru" MS Word.

Trước hết, một vài lưu ý:

- Các mẹo và thủ thuật ở đây được mô tả cho Microsoft Word. Một số chức năng tương tự cũng có thể tồn tại trong LibreOffice, nhưng bạn sẽ phải tự [công cụ tìm kiếm ưa thích] để tìm hiểu xem có thể thực hiện được hay không.
- Hãy tự giúp mình: dùng Word cho Windows và tránh hẳn Word cho Mac. Nếu bạn muốn dùng Mac làm nền tảng kiểm thử, hãy chuẩn bị một VM Windows để làm báo cáo. Word trên Mac thiếu một số tính năng cơ bản mà Word trên Windows có, không có VB Editor (phòng khi bạn cần dùng macro), và không thể tạo file PDF trông đúng và hoạt động đúng một cách tự nhiên (nó cắt margin và làm hỏng tất cả hyperlink trong mục lục), đó chỉ là một vài ví dụ.

> **Vấn đề thay đổi kích thước Pwnbox:** Hiện tại chúng tôi đang khắc phục vấn đề thay đổi kích thước Pwnbox. Vui lòng truy cập link để xem cách xử lý tạm thời: *Resolving Pwnbox VNC Resizing Issues*.

Có nhiều tính năng nâng cao hơn như font-kerning mà bạn có thể dùng để "nâng độ cầu kỳ lên mức 11" nếu muốn, nhưng chúng ta sẽ cố gắng tập trung vào những thứ giúp cải thiện hiệu suất và để dành phần sở thích thẩm mỹ cụ thể cho người đọc (hoặc bộ phận marketing của họ) quyết định.

Hãy cùng đi qua những điều cơ bản:

### Font styles (Kiểu font)

Bạn nên cố gắng hết sức để có một tài liệu không có "định dạng trực tiếp" (direct formatting) nào. Định dạng trực tiếp ở đây nghĩa là bôi đen văn bản rồi bấm nút để làm đậm, nghiêng, gạch chân, tô màu, highlight, v.v. "Nhưng tôi tưởng bạn vừa nói chỉ tập trung vào những thứ cải thiện hiệu suất?" Đúng vậy. Nếu bạn dùng font style và phát hiện ra mình đã bỏ sót một thiết lập nào đó trong một heading làm hỏng vị trí hoặc hình thức hiển thị, khi bạn cập nhật chính style đó, nó sẽ cập nhật **tất cả** các instance của style đó được dùng trong toàn bộ tài liệu, thay vì bạn phải cập nhật thủ công cả 45 lần bạn dùng heading ngẫu nhiên đó (mà thậm chí có thể vẫn bỏ sót một vài chỗ).

### Table styles (Kiểu bảng)

Áp dụng mọi điều tôi vừa nói về font style cho bảng. Cùng một khái niệm. Nó giúp việc thay đổi toàn cục dễ dàng hơn nhiều và thúc đẩy tính nhất quán trong toàn bộ báo cáo. Nó cũng nói chung làm cho tất cả mọi người sử dụng tài liệu bớt khổ sở hơn, cả với vai trò tác giả lẫn người QA.

### Captions (Chú thích)

Hãy dùng tính năng chú thích có sẵn (nhấp chuột phải vào hình ảnh hoặc bảng đã chọn rồi chọn "Insert Caption...") nếu bạn định thêm chú thích cho các thành phần. Dùng tính năng này sẽ khiến các chú thích tự động đánh số lại nếu bạn phải thêm hoặc xóa một thứ gì đó khỏi báo cáo — một việc sẽ là cơn đau đầu KHỔNG LỒ nếu làm thủ công. Tính năng này thường có sẵn một font style tích hợp cho phép bạn kiểm soát cách hiển thị chú thích.

### Page numbers (Số trang)

Số trang giúp việc tham chiếu đến các vị trí cụ thể trong tài liệu dễ dàng hơn nhiều khi cộng tác với khách hàng để trả lời câu hỏi hoặc làm rõ nội dung báo cáo (ví dụ: "Đoạn thứ hai ở trang 12 có nghĩa là gì?"). Điều tương tự cũng đúng khi khách hàng làm việc nội bộ với các đội của họ để xử lý các phát hiện.

### Table of Contents (Mục lục)

Mục lục là thành phần tiêu chuẩn của một báo cáo chuyên nghiệp. Mục lục mặc định có lẽ là ổn, nhưng nếu bạn muốn thứ gì đó tùy chỉnh, như ẩn số trang hay thay đổi ký tự dẫn (tab leader), bạn có thể chọn mục lục tùy chỉnh (custom ToC) và điều chỉnh các thiết lập.

### List of Figures/Tables (Danh mục Hình/Bảng)

Có thể tranh luận về việc có nên đưa danh mục hình hoặc bảng vào báo cáo hay không. Đây là cùng một khái niệm với mục lục, nhưng nó chỉ liệt kê các hình hoặc bảng trong báo cáo. Chúng hoạt động dựa trên các chú thích (caption), vì vậy nếu bạn không dùng caption cho một trong hai hoặc cả hai, tính năng này sẽ không hoạt động.

### Bookmarks (Dấu trang)

Bookmark thường được dùng để đánh dấu các vị trí trong tài liệu mà bạn có thể tạo hyperlink đến (như một phụ lục có tiêu đề tùy chỉnh). Nếu bạn dự định dùng macro để kết hợp các template, bạn cũng có thể dùng bookmark để chỉ định toàn bộ các phần có thể được tự động xóa khỏi báo cáo.

### Custom Dictionary (Từ điển tùy chỉnh)

Bạn có thể xem từ điển tùy chỉnh như một phần mở rộng của tính năng AutoCorrect có sẵn của Word. Nếu bạn thấy mình hay viết sai cùng một từ mỗi lần viết báo cáo, hoặc muốn tránh những lỗi đánh máy đáng xấu hổ như viết "pubic" thay vì "public", bạn có thể thêm các từ này vào từ điển tùy chỉnh, và Word sẽ tự động thay thế chúng cho bạn. Đáng tiếc là tính năng này không đi theo template, nên mỗi người sẽ phải tự cấu hình.

### Language Settings (Thiết lập ngôn ngữ)

Mục đích chính của việc dùng thiết lập ngôn ngữ tùy chỉnh có lẽ là áp dụng nó cho font style mà bạn đã tạo cho code/terminal/bằng chứng dạng văn bản (bạn đã tạo rồi đúng không?). Bạn có thể chọn tùy chọn bỏ qua kiểm tra chính tả và ngữ pháp trong thiết lập ngôn ngữ cho font style này (hoặc bất kỳ font style nào). Điều này hữu ích vì sau khi bạn xây dựng một báo cáo với hàng đống hình ảnh trong đó và muốn chạy công cụ kiểm tra chính tả, bạn không phải nhấn "ignore" cả tỷ lần để bỏ qua tất cả những thứ trong các hình.

### Custom Bullet/Numbering (Đánh dấu/đánh số tùy chỉnh)

Bạn có thể thiết lập đánh số tùy chỉnh để tự động đánh số các thứ như các phát hiện, phụ lục, và bất cứ thứ gì khác có thể hưởng lợi từ việc đánh số tự động.

### Quick Access Toolbar Setup (Thiết lập Thanh công cụ Truy cập Nhanh)

Có nhiều tùy chọn và chức năng bạn có thể thêm vào Quick Access Toolbar mà bạn nên dành thời gian xem xét để xác định mức độ hữu ích với quy trình làm việc của mình, nhưng ở đây ta sẽ liệt kê một số cái tiện dụng. Chọn **File > Options > Quick Access Toolbar** để vào phần cấu hình.

- **Back** — Luôn nên nhấp vào các hyperlink bạn tạo để đảm bảo chúng dẫn đến đúng nơi trong tài liệu. Điều khó chịu là quay lại vị trí bạn đang ở khi nhấp để tiếp tục làm việc. Nút này giải quyết việc đó.
- **Undo/Redo** — Chỉ hữu ích nếu bạn không dùng phím tắt.
- **Save** — Một lần nữa, hữu ích nếu bạn không dùng phím tắt.

Ngoài ra, bạn có thể đặt danh sách thả xuống "Choose commands from:" thành "Commands Not in the Ribbon" để duyệt qua các chức năng khó thực hiện hơn.

### Useful Hotkeys (Phím tắt hữu ích)

- **F4** sẽ áp dụng lại hành động cuối cùng bạn vừa thực hiện. Ví dụ, nếu bạn bôi đen một đoạn văn bản và áp dụng một font style cho nó, bạn có thể bôi đen một đoạn khác mà bạn muốn áp dụng cùng font style đó và chỉ cần nhấn F4 để thực hiện tương tự.
- Nếu bạn dùng mục lục và danh mục hình/bảng, bạn có thể nhấn **Ctrl+A** để chọn tất cả và **F9** để cập nhật tất cả cùng lúc. Việc này cũng sẽ cập nhật bất kỳ "field" nào khác trong tài liệu và đôi khi không hoạt động như dự kiến, vì vậy hãy tự chịu rủi ro khi dùng.
- Một phím tắt phổ biến hơn là **Ctrl+S** để lưu. Tôi nhắc đến ở đây vì bạn nên lưu thường xuyên phòng khi Word bị crash, để không mất dữ liệu.
- Nếu bạn cần xem hai khu vực khác nhau của báo cáo cùng lúc mà không muốn cuộn qua lại, bạn có thể dùng **Ctrl+Alt+S** để chia cửa sổ thành hai ngăn.
- Cái này có vẻ ngớ ngẩn, nhưng nếu bạn vô tình gõ nhầm bàn phím và không biết con trỏ của mình đang ở đâu (hoặc nơi bạn vừa chèn một ký tự lạ hay vô tình gõ điều gì đó thiếu chuyên nghiệp vào báo cáo thay vì vào Discord), bạn có thể nhấn **Shift+F5** để di chuyển con trỏ đến vị trí của lần chỉnh sửa gần nhất.

Còn nhiều phím tắt khác được liệt kê ở đây, nhưng đây là những cái mà tôi thấy hữu ích nhất và không quá hiển nhiên.

## Tự Động Hóa (Automation)

Khi phát triển template báo cáo, bạn có thể đến lúc có một tài liệu khá hoàn thiện nhưng không đủ thời gian hoặc ngân sách để mua một nền tảng báo cáo tự động. Có thể đạt được rất nhiều tự động hóa thông qua macro trong tài liệu MS Word. Bạn sẽ cần lưu template dưới dạng file `.dotm`, và bạn cần ở trong môi trường Windows để tận dụng tối đa (VB Editor của Word trên Mac coi như không tồn tại). Một số việc phổ biến nhất có thể làm với macro là:

- Tạo một macro hiển thị popup để bạn nhập các thông tin quan trọng, sau đó tự động chèn vào template báo cáo tại các biến placeholder được chỉ định:
  - Tên khách hàng
  - Ngày tháng
  - Chi tiết phạm vi (scope)
  - Loại kiểm thử
  - Tên môi trường hoặc ứng dụng
- Bạn có thể kết hợp nhiều template báo cáo khác nhau thành một tài liệu duy nhất và để macro tự động quét qua và xóa toàn bộ các phần (được chỉ định qua bookmark) không thuộc về một loại đánh giá cụ thể.
  - Điều này giúp việc duy trì template dễ dàng hơn vì bạn chỉ phải bảo trì một thay vì nhiều template.
- Bạn cũng có thể tự động hóa một số tác vụ kiểm soát chất lượng (QA) bằng cách sửa các lỗi thường mắc phải.

Vì việc viết macro Word về cơ bản là một ngôn ngữ lập trình riêng (và có thể là cả một khóa học riêng), ta để người đọc tự tìm hiểu trên các nguồn trực tuyến để học cách thực hiện những tác vụ này.

## Công Cụ Báo Cáo / Cơ Sở Dữ Liệu Các Phát Hiện (Reporting Tools/Findings Database)

Sau khi thực hiện một số đánh giá, bạn sẽ bắt đầu nhận thấy nhiều môi trường mà bạn nhắm tới gặp phải cùng những vấn đề. Nếu bạn không có cơ sở dữ liệu các phát hiện, bạn sẽ lãng phí một lượng thời gian khổng lồ để viết đi viết lại cùng một nội dung, và có nguy cơ tạo ra sự thiếu nhất quán trong các khuyến nghị cũng như mức độ kỹ lưỡng hay rõ ràng khi mô tả chính phát hiện đó. Nếu nhân các vấn đề này lên cho cả một đội, chất lượng báo cáo sẽ khác biệt rất lớn giữa các consultant. Tối thiểu, bạn nên duy trì một tài liệu riêng chứa các phiên bản đã được "làm sạch" (sanitized) của các phát hiện để có thể copy/paste vào báo cáo. Như đã thảo luận trước đó, ta nên luôn cố gắng tùy chỉnh các phát hiện cho môi trường khách hàng bất cứ khi nào hợp lý, nhưng việc có sẵn các phát hiện theo template tiết kiệm rất nhiều thời gian.

Tuy nhiên, việc dành thời gian tìm hiểu và cấu hình một trong các nền tảng có sẵn được thiết kế cho mục đích này là khoản thời gian đáng bỏ ra. Một số miễn phí, một số phải trả phí, nhưng nhiều khả năng chúng sẽ nhanh chóng tự "hoàn vốn" nhờ lượng thời gian và sự đau đầu mà bạn tiết kiệm được, nếu bạn có khả năng chi trả khoản đầu tư ban đầu.

| Miễn phí | Trả phí |
|---|---|
| Ghostwriter | AttackForge |
| Dradis | PlexTrac |
| Security Risk Advisors VECTR | Rootshell Prism |
| WriteHat | |

## Các Mẹo/Thủ Thuật Khác (Misc Tips/Tricks)

Dù ta đã đề cập một số điều trong các phần khác của module, đây là danh sách các mẹo và thủ thuật mà bạn nên luôn để sẵn bên mình:

- **Hãy cố gắng kể một câu chuyện với báo cáo của bạn.** Tại sao việc thực hiện được Kerberoasting và crack một hash lại quan trọng? Tác động của thông tin đăng nhập mặc định trên ứng dụng X là gì?
- **Viết ngay trong khi làm (Write as you go).** Đừng để báo cáo đến cuối mới làm. Báo cáo của bạn không cần hoàn hảo trong khi kiểm thử, nhưng việc ghi chép càng nhiều và càng rõ ràng càng tốt trong quá trình kiểm thử sẽ giúp bạn toàn diện nhất có thể, không bỏ sót điều gì hay làm ẩu do vội vàng vào ngày cuối của khung thời gian kiểm thử.
- **Giữ sự ngăn nắp.** Giữ mọi thứ theo thứ tự thời gian để làm việc với ghi chú dễ dàng hơn. Làm cho ghi chú của bạn rõ ràng và dễ điều hướng, để chúng mang lại giá trị và không gây thêm việc cho bạn.
- **Cung cấp càng nhiều bằng chứng càng tốt nhưng không quá dài dòng.** Hiển thị đủ ảnh chụp màn hình/output lệnh để chứng minh rõ ràng và tái hiện được các vấn đề, nhưng không thêm quá nhiều ảnh chụp màn hình thừa hay output lệnh không cần thiết làm rối báo cáo.
- **Thể hiện rõ điều đang được trình bày trong ảnh chụp màn hình.** Dùng công cụ như Greenshot để thêm mũi tên/khung màu vào ảnh chụp màn hình và thêm giải thích bên dưới ảnh nếu cần. Một ảnh chụp màn hình vô dụng nếu khán giả phải đoán xem bạn muốn thể hiện gì qua nó.
- **Che (redact) dữ liệu nhạy cảm bất cứ khi nào có thể.** Bao gồm mật khẩu cleartext, password hash, các bí mật khác, và bất kỳ dữ liệu nào có thể bị coi là nhạy cảm đối với khách hàng. Báo cáo có thể được gửi đi trong công ty và thậm chí đến bên thứ ba, nên ta muốn đảm bảo đã làm tròn trách nhiệm để không đưa vào báo cáo bất kỳ dữ liệu nào có thể bị lạm dụng. Có thể dùng công cụ như Greenshot để che phần của ảnh chụp màn hình (dùng hình khối đặc chứ không dùng làm mờ - blur!).
- **Che output của công cụ** để loại bỏ những thành phần mà người không phải hacker có thể coi là thiếu chuyên nghiệp (ví dụ: `(Pwn3d!)` trong output của CrackMapExec). Với CME, bạn có thể thay đổi giá trị đó trong file cấu hình để in ra thứ khác lên màn hình, để không phải sửa trong báo cáo mỗi lần. Các công cụ khác có thể có tùy chỉnh tương tự.
- **Kiểm tra output Hashcat của bạn** để đảm bảo không có mật khẩu ứng viên nào thô tục. Nhiều wordlist có những từ có thể bị coi là thô tục/xúc phạm, và nếu bất kỳ từ nào xuất hiện trong output Hashcat, hãy đổi chúng thành thứ gì đó vô hại. Bạn có thể nghĩ, "họ đã nói không bao giờ được chỉnh sửa output lệnh". Hai ví dụ trên là một trong số ít trường hợp được phép. Nói chung, nếu ta sửa thứ gì đó có thể bị coi là xúc phạm hoặc thiếu chuyên nghiệp nhưng không làm thay đổi cách thể hiện tổng thể của bằng chứng phát hiện, thì không sao, nhưng hãy xử lý theo từng trường hợp và báo cho quản lý hoặc trưởng nhóm nếu còn nghi ngờ.
- **Kiểm tra ngữ pháp, chính tả và định dạng**, đảm bảo font và cỡ chữ nhất quán, và viết đầy đủ các từ viết tắt ở lần đầu tiên sử dụng trong báo cáo.
- **Đảm bảo ảnh chụp màn hình rõ ràng** và không chụp thừa các phần khác của màn hình làm phình kích thước. Nếu báo cáo của bạn khó đọc do định dạng kém hoặc ngữ pháp và chính tả lộn xộn, nó sẽ làm giảm giá trị của kết quả kỹ thuật của đánh giá. Hãy cân nhắc dùng công cụ như Grammarly hoặc LanguageTool (nhưng cần lưu ý các công cụ này có thể gửi một số dữ liệu của bạn lên cloud để "học"), mạnh hơn nhiều so với công cụ kiểm tra chính tả và ngữ pháp có sẵn của Microsoft Word.
- **Dùng output lệnh thô (raw) khi có thể**, nhưng khi cần chụp màn hình console, hãy đảm bảo nó không trong suốt và không hiển thị hình nền/các công cụ khác (trông rất tệ). Console nên có nền đen đặc với theme hợp lý (nền đen, chữ trắng hoặc xanh lá, không phải theme nhiều màu kỳ quặc gây nhức mắt cho người đọc). Khách hàng có thể in báo cáo ra, nên bạn có thể cân nhắc dùng nền sáng với chữ tối để không "hủy diệt" hộp mực máy in của họ.
- **Giữ hostname và username chuyên nghiệp.** Đừng đưa ảnh chụp màn hình có prompt như `azzkicker@clientsmasher`.
- **Thiết lập quy trình QA.** Báo cáo của bạn nên trải qua ít nhất một, tốt nhất là hai vòng QA (hai người review ngoài bản thân bạn). Ta không bao giờ nên tự review công việc của mình (bất cứ khi nào có thể) và muốn tạo ra sản phẩm bàn giao tốt nhất có thể, vì vậy hãy chú ý đến quy trình QA. Tối thiểu, nếu bạn làm độc lập, hãy "ngủ một đêm" rồi review lại. Rời xa báo cáo một thời gian đôi khi giúp bạn nhìn ra những điều bạn bỏ sót sau khi nhìn chằm chằm vào nó quá lâu.
- **Thiết lập style guide và tuân thủ nó**, để mọi người trong đội đều theo cùng một định dạng tương tự và các báo cáo nhất quán với nhau trong tất cả các đánh giá.
- **Dùng tính năng tự động lưu (autosave)** với công cụ ghi chú và MS Word. Bạn không muốn mất hàng giờ công việc vì một chương trình bị crash. Ngoài ra, hãy sao lưu ghi chú và dữ liệu khác trong quá trình làm việc, và đừng lưu mọi thứ trên một VM duy nhất. VM có thể hỏng, nên bạn cần di chuyển bằng chứng sang nơi lưu trữ thứ hai trong quá trình làm việc. Đây là việc có thể và nên được tự động hóa.
- **Viết script và tự động hóa bất cứ khi nào có thể.** Điều này đảm bảo công việc của bạn nhất quán trong tất cả các đánh giá và bạn không lãng phí thời gian cho các tác vụ lặp lại ở mọi đánh giá.

## Giao Tiếp Với Khách Hàng (Client Communication)

Kỹ năng giao tiếp bằng văn bản và lời nói tốt là điều tối quan trọng với bất kỳ ai làm trong vai trò pentest. Trong suốt các dự án (từ lúc xác định phạm vi cho đến khi bàn giao và review báo cáo cuối cùng), ta phải luôn giữ liên lạc thường xuyên với khách hàng và đóng vai trò phù hợp là người cố vấn đáng tin cậy (trusted advisor). Họ thuê công ty ta và trả rất nhiều tiền để ta xác định các vấn đề trong mạng của họ, đưa ra lời khuyên khắc phục, và cũng để giáo dục nhân viên của họ về những vấn đề ta tìm thấy thông qua báo cáo bàn giao. Vào đầu mỗi dự án, ta nên gửi email thông báo bắt đầu (start notification) bao gồm các thông tin như:

- Tên tester
- Mô tả loại/phạm vi của dự án
- Địa chỉ IP nguồn dùng để kiểm thử (IP công khai của máy tấn công bên ngoài, hoặc IP nội bộ của máy tấn công nếu ta thực hiện Internal Penetration Test)
- Các ngày dự kiến kiểm thử
- Thông tin liên hệ chính và phụ (email và số điện thoại)

Vào cuối mỗi ngày, ta nên gửi thông báo kết thúc (stop notification) để báo hiệu kết thúc kiểm thử. Đây có thể là thời điểm tốt để tóm tắt cấp cao các phát hiện (đặc biệt nếu báo cáo sẽ có 20+ phát hiện mức rủi ro cao) để báo cáo không khiến khách hàng hoàn toàn bất ngờ. Ta cũng có thể nhắc lại kỳ vọng về thời gian giao báo cáo vào lúc này. Dĩ nhiên ta nên làm báo cáo dần dần chứ không để 100% đến phút chót, nhưng có thể mất vài ngày để viết toàn bộ attack chain, executive summary, các phát hiện, khuyến nghị, và thực hiện các bước tự kiểm tra QA. Sau đó, báo cáo nên trải qua ít nhất một vòng QA nội bộ (và những người phụ trách QA có lẽ còn nhiều việc khác phải làm), có thể mất một khoảng thời gian.

Các thông báo bắt đầu và kết thúc cũng cho khách hàng một khung thời gian về việc các bản quét và hoạt động kiểm thử của ta diễn ra khi nào, phòng khi họ cần truy tìm các cảnh báo.

Ngoài các liên lạc chính thức này, việc duy trì đối thoại cởi mở với khách hàng và xây dựng, củng cố mối quan hệ cố vấn đáng tin cậy là điều tốt. Bạn phát hiện thêm một subnet hoặc subdomain bên ngoài? Hãy hỏi khách hàng xem họ có muốn thêm vào phạm vi không (trong giới hạn hợp lý và với điều kiện không vượt quá thời gian được phân bổ cho kiểm thử). Bạn phát hiện một lỗ hổng SQL injection hoặc thực thi mã từ xa mức độ rủi ro cao trên một website bên ngoài? Hãy dừng kiểm thử và thông báo chính thức cho khách hàng rồi xem họ muốn tiến hành như thế nào. Một host dường như bị "down" do quét? Điều đó có thể xảy ra, và tốt nhất là nên thẳng thắn về nó hơn là cố che giấu. Có được Domain Admin/Enterprise Admin? Hãy báo trước cho khách hàng phòng khi họ thấy cảnh báo và lo lắng, hoặc để họ chuẩn bị cho ban quản lý về báo cáo sắp tới. Ngoài ra, lúc này hãy cho họ biết rằng bạn sẽ tiếp tục kiểm thử và tìm các đường tấn công khác, nhưng hỏi họ xem có điều gì khác họ muốn bạn tập trung vào, hoặc server/cơ sở dữ liệu nào vẫn cần được hạn chế ngay cả khi có quyền DA mà bạn có thể nhắm tới.

Ta cũng nên bàn về tầm quan trọng của ghi chú chi tiết và log của scanner/output của công cụ. Nếu khách hàng hỏi bạn có tác động vào một host cụ thể vào ngày X hay không, bạn phải có thể cung cấp, không chút nghi ngờ, bằng chứng được ghi chép lại về các hoạt động chính xác của mình. Bị đổ lỗi cho một sự cố ngừng hoạt động (outage) đã là điều tệ, nhưng còn tệ hơn nếu bạn bị đổ lỗi mà không có bất kỳ bằng chứng cụ thể nào để chứng minh nó không phải kết quả của quá trình kiểm thử của mình.

Ghi nhớ những mẹo giao tiếp này sẽ giúp ích rất nhiều trong việc xây dựng thiện cảm với khách hàng và giành được hợp đồng lặp lại cũng như giới thiệu khách hàng mới. Mọi người muốn làm việc với những người đối xử tốt với họ và làm việc siêng năng, chuyên nghiệp, vì vậy đây là lúc bạn tỏa sáng. Với kỹ năng kỹ thuật xuất sắc cùng kỹ năng giao tiếp xuất sắc, bạn sẽ không thể ngăn cản!

## Trình Bày Báo Cáo — Sản Phẩm Cuối Cùng

Khi báo cáo đã sẵn sàng, nó cần trải qua bước review trước khi bàn giao. Sau khi bàn giao, theo thông lệ sẽ có một buổi họp review báo cáo với khách hàng để đi qua toàn bộ báo cáo, chỉ các phát hiện, hoặc trả lời các câu hỏi mà họ có thể có.

### Quy Trình QA

Một báo cáo cẩu thả sẽ khiến mọi thứ về đánh giá của ta bị đặt dấu hỏi. Nếu báo cáo của ta là một mớ hỗn độn thiếu tổ chức, liệu ta có thực sự đã thực hiện một đánh giá kỹ lưỡng? Có phải ta đã bất cẩn và để lại một đường tàn phá phía sau mà khách hàng sẽ phải mất thời gian (mà họ không có) để dọn dẹp? Hãy đảm bảo sản phẩm báo cáo của ta là minh chứng cho kiến thức khó khăn lắm mới có và công sức làm việc trong đánh giá, và phản ánh đầy đủ cả hai. Khách hàng sẽ không thấy phần lớn những gì bạn làm trong quá trình đánh giá.

**Báo cáo là "đoạn video highlight" của bạn và thành thật mà nói, đó là thứ khách hàng đang trả tiền cho!**

Bạn có thể đã thực hiện attack chain phức tạp và tuyệt vời nhất trong lịch sử các attack chain, nhưng nếu bạn không thể đưa nó lên giấy theo cách để người khác hiểu được, thì coi như nó chưa từng xảy ra.

Nếu có thể, mỗi báo cáo nên trải qua ít nhất một vòng QA bởi một người không phải là tác giả. Một số đội cũng có thể chọn chia quy trình QA thành nhiều bước (ví dụ: QA về độ chính xác kỹ thuật, rồi QA về phong cách và thẩm mỹ). Việc chọn cách tiếp cận phù hợp với quy mô đội sẽ do bạn, đội của bạn, hoặc tổ chức của bạn quyết định. Nếu bạn mới bắt đầu một mình và không có điều kiện nhờ người khác review báo cáo, tôi thực sự khuyến nghị tối thiểu là hãy rời xa nó một lúc hoặc "ngủ một đêm" rồi review lại. Khi bạn đọc một tài liệu 45 lần, bạn bắt đầu bỏ sót nhiều thứ. Việc "reset nhỏ" này có thể giúp bạn bắt được những thứ bạn không thấy sau khi nhìn chằm chằm vào nó nhiều ngày liền.

Nên đưa một **danh sách kiểm tra QA (QA checklist)** vào template báo cáo của bạn như một thực hành tốt (xóa nó khi báo cáo đã hoàn tất). Danh sách này nên bao gồm tất cả các kiểm tra mà tác giả cần thực hiện về nội dung và định dạng, cùng bất cứ điều gì khác bạn có trong style guide. Danh sách này có thể sẽ dài ra theo thời gian khi quy trình của bạn và đội được tinh chỉnh, và bạn học được những lỗi mà mọi người dễ mắc phải nhất. Hãy chắc chắn kiểm tra ngữ pháp, chính tả và định dạng! Công cụ như Grammarly hoặc LanguageTool rất tuyệt cho việc này (nhưng hãy đảm bảo bạn đã được cho phép). Đừng gửi một báo cáo cẩu thả đến QA vì nó có thể bị trả lại cho bạn để sửa trước khi người review kịp nhìn qua, và đó có thể là sự lãng phí thời gian tốn kém cho bạn và những người khác.

> **Lưu ý nhanh về các công cụ sửa ngữ pháp trực tuyến:** Để "học" thêm và cải thiện độ chính xác của công cụ, chúng thường gửi các phần dữ liệu mà nó đang đọc về "nhà" (server của họ), nghĩa là nếu bạn đang viết một báo cáo có dữ liệu lỗ hổng bảo mật bí mật của khách hàng, bạn có thể đang vô tình vi phạm một hợp đồng dịch vụ chính (MSA) nào đó. Trước khi dùng các công cụ như vậy, điều quan trọng là phải tìm hiểu chức năng của chúng và xem liệu hành vi này có thể tắt được hay không.

Nếu bạn có người có thể thực hiện QA và bắt đầu cố gắng triển khai một quy trình, bạn có thể sớm nhận ra rằng khi đội lớn lên và số lượng báo cáo được xuất ra tăng lên, mọi thứ có thể trở nên khó theo dõi. Ở mức cơ bản, một Google Sheet hoặc công cụ tương đương có thể được dùng để giúp đảm bảo mọi thứ không bị thất lạc, nhưng nếu bạn có nhiều người hơn (như cả consultant VÀ PM) và có quyền truy cập một công cụ như Jira, đó có thể là giải pháp mở rộng tốt hơn nhiều. Bạn có thể sẽ cần một nơi tập trung để lưu trữ các báo cáo để những người khác có thể truy cập để thực hiện quá trình QA. Có nhiều công cụ có thể dùng được, nhưng việc chọn cái tốt nhất nằm ngoài phạm vi của khóa học này.

Lý tưởng nhất, người thực hiện QA **KHÔNG** nên chịu trách nhiệm thực hiện những chỉnh sửa lớn cho báo cáo. Nếu có các lỗi đánh máy nhỏ, cách diễn đạt, hoặc vấn đề định dạng cần xử lý mà có thể làm nhanh hơn việc gửi báo cáo lại cho tác giả để sửa, thì điều đó có lẽ ổn. Đối với bằng chứng bị thiếu hoặc minh họa kém, phát hiện bị thiếu, nội dung executive summary không dùng được, v.v., tác giả nên chịu trách nhiệm đưa tài liệu đó về trạng thái có thể trình bày được.

Rõ ràng bạn cần cẩn thận xem xét các thay đổi được thực hiện trên báo cáo của mình (hãy bật Track Changes!) để có thể ngừng mắc cùng những lỗi trong các báo cáo tiếp theo. Đây chắc chắn là một cơ hội học hỏi, vì vậy đừng lãng phí nó. Nếu đó là điều xảy ra ở nhiều người, bạn có thể cân nhắc thêm mục đó vào QA checklist để nhắc mọi người xử lý những vấn đề đó trước khi gửi báo cáo đến QA. Không có nhiều cảm giác nào trong sự nghiệp này tuyệt hơn khi đến ngày báo cáo bạn viết vượt qua QA mà không có bất kỳ thay đổi nào.

Có thể coi đây hoàn toàn chỉ là thủ tục, nhưng việc ban đầu phát hành một bản "**Draft**" (bản nháp) của báo cáo cho khách hàng sau khi quy trình QA hoàn tất là khá phổ biến. Khi khách hàng đã có bản nháp, họ được kỳ vọng sẽ xem xét và cho bạn biết liệu họ có muốn có cơ hội cùng bạn đi qua báo cáo để thảo luận các sửa đổi và đặt câu hỏi hay không. Nếu có bất kỳ thay đổi hoặc cập nhật nào cần thực hiện với báo cáo sau cuộc trao đổi này, chúng có thể được thực hiện và một phiên bản "**Final**" (chính thức) được phát hành. Báo cáo Final thường sẽ giống hệt báo cáo Draft (nếu khách hàng không có thay đổi nào cần thực hiện), chỉ khác là ghi "Final" thay vì "Draft". Điều này có vẻ phù phiếm, nhưng một số kiểm toán viên chỉ chấp nhận báo cáo chính thức (final) làm hiện vật (artifact), nên nó có thể khá quan trọng đối với một số khách hàng.

### Họp Review Báo Cáo (Report Review Meeting)

Sau khi báo cáo đã được bàn giao, theo thông lệ, ta cho khách hàng khoảng một tuần để xem xét báo cáo, thu thập suy nghĩ của họ, và đề nghị một cuộc gọi để cùng review và thu thập bất kỳ phản hồi nào họ có về công việc của bạn. Thông thường, cuộc gọi này đi qua các chi tiết kỹ thuật của từng phát hiện một, và cho phép khách hàng đặt câu hỏi về những gì bạn tìm thấy và cách bạn tìm thấy chúng. Những cuộc gọi này có thể cực kỳ hữu ích trong việc cải thiện khả năng trình bày loại dữ liệu này của bạn, vì vậy hãy chú ý cẩn thận đến cuộc trò chuyện. Nếu bạn thấy mình trả lời cùng những câu hỏi mỗi lần, điều đó có thể cho thấy bạn cần điều chỉnh quy trình làm việc hoặc thông tin bạn cung cấp để giải đáp những câu hỏi đó trước khi khách hàng hỏi.

Khi báo cáo đã được cả hai bên xem xét và chấp nhận, theo thông lệ, ta đổi ký hiệu **DRAFT** thành **FINAL** và bàn giao bản cuối cho khách hàng. Từ đây, ta nên lưu trữ toàn bộ dữ liệu kiểm thử của mình theo chính sách lưu giữ của công ty, ít nhất là cho đến khi việc kiểm tra lại (retest) các phát hiện đã khắc phục được thực hiện.

## Tổng Kết (Wrap Up)

Đây chỉ là một số mẹo và thủ thuật mà chúng tôi đã thu thập qua nhiều năm. Nhiều điều trong số này là lẽ thường. Bài viết này của đội ngũ tuyệt vời tại Black Hills Information Security cũng đáng đọc. Mục tiêu ở đây là trình bày sản phẩm bàn giao chuyên nghiệp nhất có thể, đồng thời kể một câu chuyện rõ ràng dựa trên công sức của ta trong một đánh giá kỹ thuật. Hãy thể hiện hết khả năng của mình và tạo ra một sản phẩm bàn giao mà bạn có thể tự hào. Bạn đã dành nhiều giờ không ngừng nghỉ để theo đuổi Domain Admin. Hãy áp dụng cùng nhiệt huyết đó cho việc làm báo cáo, và bạn sẽ là một ngôi sao (rockstar). Trong các phần cuối của module này, ta sẽ thảo luận về các cơ hội để thực hành kỹ năng lập tài liệu và viết báo cáo.

---

*Tài liệu gốc: [Reporting Tips and Tricks | Hack The Box Academy](https://academy.hackthebox.com/app/module/162/section/1539)*
