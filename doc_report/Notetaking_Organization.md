# Ghi chép & Tổ chức (Notetaking & Organization)
*Hack The Box Academy*

---

Việc ghi chép cẩn thận là yếu tố cực kỳ quan trọng trong bất kỳ đợt đánh giá (assessment) nào. Ghi chú của chúng ta, cùng với output của công cụ và log, chính là đầu vào thô cho bản báo cáo nháp — thứ mà thường là phần duy nhất khách hàng nhìn thấy từ toàn bộ quá trình đánh giá. Dù ghi chú thường chỉ để chúng ta tự dùng, ta vẫn cần giữ mọi thứ có tổ chức và xây dựng một quy trình lặp lại được để tiết kiệm thời gian và hỗ trợ việc viết báo cáo sau này.

Ghi chú chi tiết cũng rất cần thiết trong trường hợp có sự cố mạng hoặc câu hỏi từ khách hàng (ví dụ: "bạn có scan host X vào ngày Y không?"), vì vậy việc ghi chép dài dòng một chút không bao giờ là thừa. Mỗi người sẽ có phong cách riêng mà họ cảm thấy thoải mái, và nên làm việc với công cụ cũng như cấu trúc tổ chức mà mình quen thuộc để đạt kết quả tốt nhất. Trong module này, chúng ta sẽ đề cập đến những yếu tố tối thiểu mà theo kinh nghiệm chuyên môn, nên được ghi lại trong quá trình đánh giá (hoặc thậm chí khi làm một module lớn, chơi một box trên HTB, hay thi chứng chỉ) để tiết kiệm thời gian, công sức khi viết báo cáo hoặc dùng làm tài liệu tham khảo sau này. Nếu bạn thuộc một nhóm lớn, nơi ai đó có thể phải thay bạn tham dự cuộc họp với khách hàng, thì việc ghi chép rõ ràng và nhất quán là điều thiết yếu để đồng đội có thể tự tin và chính xác khi trình bày về những gì đã và chưa được thực hiện.

## Cấu trúc ghi chép mẫu

Không có một giải pháp hay cấu trúc chung nào cho việc ghi chép vì mỗi dự án và mỗi tester đều khác nhau. Cấu trúc dưới đây là những gì đội ngũ HTB nhận thấy hữu ích, nhưng nên được điều chỉnh theo quy trình làm việc cá nhân, loại dự án, và hoàn cảnh cụ thể gặp phải trong dự án. Ví dụ, một số mục dưới đây có thể không áp dụng được cho một bài đánh giá tập trung vào ứng dụng, và thậm chí có thể cần thêm các mục khác không được liệt kê ở đây.

- **Attack Path (Đường tấn công)** – Một bản phác thảo toàn bộ đường đi nếu bạn đạt được chỗ đứng ban đầu (foothold) trong một bài kiểm tra thâm nhập từ bên ngoài (external), hoặc xâm nhập được một hay nhiều host (hoặc domain AD) trong một bài kiểm tra nội bộ (internal). Việc phác thảo đường đi càng chi tiết càng tốt bằng ảnh chụp màn hình và output lệnh sẽ giúp việc dán vào báo cáo sau này dễ dàng hơn, chỉ cần lo phần định dạng.
- **Credentials (Thông tin đăng nhập)** – Nơi tập trung để lưu các thông tin đăng nhập và bí mật đã chiếm được trong quá trình thực hiện.
- **Findings (Phát hiện)** – Khuyến nghị tạo một thư mục con cho mỗi phát hiện, sau đó viết phần tường thuật (narrative) và lưu vào thư mục đó cùng với các bằng chứng (ảnh chụp màn hình, output lệnh). Cũng nên có một phần trong công cụ ghi chép để ghi lại thông tin về các phát hiện, giúp tổ chức chúng cho báo cáo.
- **Vulnerability Scan Research (Nghiên cứu quét lỗ hổng)** – Phần ghi chú về những gì đã nghiên cứu và thử nghiệm với công cụ quét lỗ hổng (để không phải làm lại công việc đã làm).
- **Service Enumeration Research (Nghiên cứu liệt kê dịch vụ)** – Phần ghi chú về các dịch vụ đã điều tra, các lần khai thác thất bại, các lỗ hổng/cấu hình sai tiềm năng, v.v.

> **Sự cố resize Pwnbox:** Đội ngũ HTB hiện đang khắc phục lỗi resize trên Pwnbox. Vui lòng xem liên kết "Resolving Pwnbox VNC Resizing Issues" trong tài liệu gốc để biết cách khắc phục tạm thời.

- **Web Application Research (Nghiên cứu ứng dụng web)** – Phần ghi chú về các ứng dụng web thú vị tìm được qua nhiều phương pháp khác nhau, như brute-force subdomain. Luôn nên thực hiện liệt kê subdomain kỹ lưỡng ở bên ngoài, quét các cổng web phổ biến trong đánh giá nội bộ, và chạy công cụ như Aquatone hoặc EyeWitness để chụp màn hình tất cả ứng dụng. Khi xem báo cáo ảnh chụp, ghi lại các ứng dụng đáng chú ý, các cặp thông tin đăng nhập mặc định/thông dụng đã thử, v.v.
- **AD Enumeration Research (Nghiên cứu liệt kê Active Directory)** – Phần trình bày từng bước những gì đã thực hiện để liệt kê Active Directory. Ghi lại các khu vực cần điều tra thêm sau này trong quá trình đánh giá.
- **OSINT** – Phần lưu thông tin thú vị thu thập được qua OSINT, nếu có áp dụng cho dự án.
- **Administrative Information (Thông tin hành chính)** – Một số người thấy hữu ích khi có một nơi tập trung để lưu thông tin liên hệ của các bên liên quan trong dự án như Project Manager (PM) hay đầu mối liên hệ (POC) phía khách hàng, các mục tiêu/flag riêng được định nghĩa trong Rules of Engagement (RoE), và các mục khác thường xuyên cần tham chiếu trong suốt dự án. Nó cũng có thể dùng như một danh sách việc cần làm (to-do list). Khi có ý tưởng kiểm thử nảy ra mà bạn cần thực hiện hoặc muốn thử nhưng chưa có thời gian, hãy cẩn thận ghi lại ở đây để quay lại sau.
- **Scoping Information (Thông tin phạm vi)** – Nơi lưu thông tin về các dải IP/CIDR trong phạm vi, các URL ứng dụng web, và bất kỳ thông tin đăng nhập nào cho ứng dụng web, VPN, hoặc AD do khách hàng cung cấp. Có thể bao gồm cả những thứ khác liên quan đến phạm vi đánh giá để không phải mở lại thông tin phạm vi nhiều lần và đảm bảo không đi lệch khỏi phạm vi đánh giá.
- **Activity Log (Nhật ký hoạt động)** – Theo dõi ở mức tổng quan mọi hoạt động đã thực hiện trong quá trình đánh giá để phục vụ việc đối chiếu sự kiện (event correlation) nếu cần.
- **Payload Log (Nhật ký payload)** – Tương tự activity log, việc theo dõi các payload đang sử dụng (cùng với hash file cho bất kỳ thứ gì đã upload và vị trí upload) trong môi trường khách hàng là cực kỳ quan trọng. Sẽ nói thêm về việc này sau.

## Công cụ ghi chép

Có rất nhiều công cụ ghi chép, và việc lựa chọn hoàn toàn phụ thuộc vào sở thích cá nhân. Một số lựa chọn:

CherryTree · Visual Studio Code · Evernote · Notion · GitBook · Sublime Text · Notepad++ · OneNote · Outline · Obsidian · Cryptpad · Standard Notes

Đội ngũ HTB đã có nhiều thảo luận về ưu nhược điểm của các công cụ ghi chép khác nhau. Một yếu tố quan trọng là phân biệt giữa giải pháp local và cloud trước khi chọn công cụ. Giải pháp cloud có thể chấp nhận được cho các khóa đào tạo, CTF, lab, v.v., nhưng khi bước vào các dự án thực tế và xử lý dữ liệu khách hàng, cần phải cẩn trọng hơn với giải pháp lựa chọn. Công ty của bạn thường sẽ có chính sách hoặc ràng buộc hợp đồng về việc lưu trữ dữ liệu, vì vậy tốt nhất nên trao đổi với quản lý hoặc trưởng nhóm về việc có được phép dùng một công cụ ghi chép cụ thể hay không.

Obsidian là một giải pháp tuyệt vời cho lưu trữ local, còn Outline rất tốt cho cloud nhưng cũng có phiên bản self-hosted. Cả hai công cụ đều có thể export sang Markdown và import vào bất kỳ công cụ nào khác hỗ trợ định dạng tiện lợi này.

### Obsidian

<img width="1336" height="884" alt="image" src="https://github.com/user-attachments/assets/3a625071-1646-4e29-8562-ee2d42008b6e" />


Một lần nữa, công cụ là sở thích cá nhân của từng người. Yêu cầu thường thay đổi tùy công ty, vì vậy hãy thử nghiệm với nhiều lựa chọn khác nhau và tìm ra công cụ mà bạn cảm thấy thoải mái; hãy thực hành với nhiều cách bố trí và định dạng khác nhau khi làm các module Academy, box HTB, Pro Labs, và các bài đào tạo khác để làm quen với phong cách ghi chép của mình trong khi vẫn giữ được sự kỹ lưỡng tối đa.

---

## Ghi log (Logging)

Việc log lại toàn bộ các lần scan và tấn công, đồng thời giữ output thô của công cụ bất cứ khi nào có thể, là điều thiết yếu. Điều này sẽ giúp ích rất nhiều khi viết báo cáo. Dù ghi chú của chúng ta cần rõ ràng và đầy đủ, ta vẫn có thể bỏ sót điều gì đó, và việc có log để dự phòng sẽ giúp ích khi cần bổ sung bằng chứng cho báo cáo hoặc trả lời câu hỏi của khách hàng.

### Các lần thử khai thác (Exploitation Attempts)

Ghi log Tmux là một lựa chọn tuyệt vời cho việc log terminal, và chúng ta nên sử dụng Tmux kết hợp với việc ghi log vì nó sẽ lưu lại mọi thứ gõ vào một pane Tmux ra file log. Việc theo dõi các lần thử khai thác cũng rất quan trọng trong trường hợp khách hàng cần đối chiếu sự kiện sau này (hoặc trong tình huống có rất ít phát hiện và họ đặt câu hỏi về công việc đã thực hiện). Sẽ vô cùng bẽ mặt nếu bạn không thể cung cấp thông tin này, và điều đó khiến bạn trông thiếu kinh nghiệm và thiếu chuyên nghiệp với vai trò một pentester. Đây cũng là cách tốt để theo dõi những gì đã thử nhưng không thành công trong quá trình đánh giá. Điều này đặc biệt hữu ích trong trường hợp báo cáo có ít hoặc không có phát hiện nào — khi đó ta có thể viết một bản tường thuật về các loại kiểm thử đã thực hiện, để người đọc hiểu được những gì hệ thống đã được bảo vệ tốt. Có thể thiết lập ghi log Tmux trên hệ thống như sau:

Đầu tiên, clone repo Tmux Plugin Manager về thư mục home (trong trường hợp này là `/home/htb-student` hoặc chỉ `~`).

```shellsession
naruto3co@htb[/htb]$ git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
```

Tiếp theo, tạo file `.tmux.conf` trong thư mục home.

```shellsession
naruto3co@htb[/htb]$ touch .tmux.conf
```

File cấu hình nên có nội dung như sau:

```shellsession
naruto3co@htb[/htb]$ cat .tmux.conf

# List of plugins
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'

# Initialize TMUX plugin manager (keep at bottom)
run '~/.tmux/plugins/tpm/tpm'
```

Sau khi tạo file cấu hình này, ta cần thực thi nó trong phiên hiện tại để các thiết lập trong `.tmux.conf` có hiệu lực. Có thể làm điều này bằng lệnh `source`.

```shellsession
naruto3co@htb[/htb]$ tmux source ~/.tmux.conf
```

Tiếp theo, khởi động một phiên Tmux mới (ví dụ: `tmux new -s setup`).

[<img width="812" height="582" alt="image" src="https://github.com/user-attachments/assets/6fdc0eb4-b697-4a69-b0df-984ad15a4f1f" />](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/162/tmux_log_enable.gif)


Khi vào trong phiên, gõ `[Ctrl] + [B]` rồi nhấn `[Shift] + [I]` (hoặc `prefix + [Shift] + [I]` nếu bạn không dùng phím prefix mặc định), plugin sẽ được cài đặt (có thể mất khoảng 5 giây để hoàn tất).

Sau khi plugin được cài, bắt đầu ghi log phiên (hoặc pane) hiện tại bằng cách gõ `[Ctrl] + [B]` rồi `[Shift] + [P]` (`prefix + [Shift] + [P]`) để bắt đầu ghi log. Nếu mọi thứ diễn ra đúng kế hoạch, phía dưới cửa sổ sẽ hiển thị rằng việc ghi log đã được bật cùng với file output. Để dừng ghi log, lặp lại tổ hợp phím `prefix + [Shift] + [P]` hoặc gõ `exit` để kết thúc phiên. Lưu ý rằng file log chỉ được ghi đầy đủ sau khi bạn dừng ghi log hoặc thoát phiên Tmux.

Sau khi ghi log hoàn tất, bạn có thể tìm thấy toàn bộ lệnh và output trong file log tương ứng.

Nếu quên bật ghi log Tmux và đã đi sâu vào dự án, ta có thể thực hiện ghi log hồi tố (retroactive logging) bằng cách gõ `[Ctrl] + [B]` rồi nhấn `[Alt] + [Shift] + [P]` (`prefix + [Alt] + [Shift] + [P]`), và toàn bộ pane sẽ được lưu lại. Lượng dữ liệu được lưu phụ thuộc vào `history-limit` của Tmux hoặc số dòng được giữ trong bộ đệm scrollback của Tmux. Nếu để giá trị mặc định và cố thực hiện ghi log hồi tố, rất có thể sẽ mất dữ liệu từ đầu buổi đánh giá. Để phòng ngừa tình huống này, có thể thêm các dòng sau vào file `.tmux.conf` (điều chỉnh số dòng tùy ý):

**Tmux.conf**

```shellsession
set -g history-limit 50000
```

Một mẹo hữu ích khác là khả năng chụp lại (screen capture) cửa sổ Tmux hiện tại hoặc một pane riêng lẻ. Giả sử ta đang làm việc với một cửa sổ chia đôi (2 pane), một pane chạy Responder và một pane chạy `ntlmrelayx.py`. Nếu cố copy/paste output từ một pane, ta sẽ vô tình lấy luôn dữ liệu từ pane còn lại, khiến kết quả lộn xộn và cần dọn dẹp. Có thể tránh điều này bằng cách chụp màn hình như sau: `[Ctrl] + [B]` rồi `[Alt] + [P]` (`prefix + [Alt] + [P]`).

Ở đây ta có thể thấy đang làm việc với hai pane. Nếu cố copy text từ một pane, ta sẽ lấy luôn text từ pane còn lại, gây lộn xộn cho output. Nhưng với tính năng ghi log Tmux được bật, ta có thể chụp lại pane và xuất ra file một cách gọn gàng.

<img width="812" height="582" alt="image" src="https://github.com/user-attachments/assets/fc226d80-af2a-4acf-a13f-c8954d9efbd6" />


Để tái tạo lại ví dụ trên, đầu tiên khởi động một phiên tmux mới: `tmux new -s sessionname`. Sau đó trong phiên, gõ `[Ctrl] + [B] + [Shift] + [%]` (`prefix + [Shift] + [%]`) để chia pane theo chiều dọc (thay `[%]` bằng `["]` để chia theo chiều ngang). Sau đó có thể di chuyển giữa các pane bằng cách gõ `[Ctrl] + [B] + [O]` (`prefix + [O]`).

Cuối cùng, có thể xóa lịch sử của pane bằng cách gõ `[Ctrl] + [B]` rồi `[Alt] + [C]` (`prefix + [Alt] + [C]`).

Còn rất nhiều điều khác có thể làm với Tmux, các tùy chỉnh cho việc ghi log Tmux (ví dụ: thay đổi đường dẫn log mặc định, thay đổi phím tắt, chạy nhiều cửa sổ trong các phiên và pane trong các cửa sổ đó, v.v.). Rất đáng để tìm hiểu thêm về mọi khả năng mà Tmux cung cấp và xem công cụ này phù hợp với quy trình làm việc của bạn ra sao. Cuối cùng, đây là một số plugin bổ sung được ưa thích:

- **tmux-sessionist** – Cho phép thao tác với các phiên Tmux ngay từ bên trong một phiên: chuyển sang phiên khác, tạo phiên mới có tên, kết thúc một phiên mà không cần detach Tmux, đưa pane hiện tại thành một phiên mới, và nhiều hơn nữa.
- **tmux-pain-control** – Plugin giúp điều khiển pane và cung cấp các phím tắt trực quan hơn để di chuyển, thay đổi kích thước, và chia pane.
- **tmux-resurrect** – Plugin cực kỳ tiện lợi này cho phép khôi phục lại môi trường Tmux sau khi host khởi động lại. Một số tính năng bao gồm khôi phục toàn bộ phiên, cửa sổ, pane cùng thứ tự của chúng, khôi phục các chương trình đang chạy trong pane, khôi phục phiên Vim, và nhiều hơn nữa.

Có thể xem đầy đủ danh sách plugin Tmux để tìm thêm những plugin phù hợp với quy trình làm việc của bạn. Để tìm hiểu thêm về Tmux, có thể xem video hướng dẫn xuất sắc của Ippsec và bảng cheat sheet dựa trên video đó.

---

## Các tài liệu để lại (Artifacts Left Behind)

Tối thiểu, chúng ta nên theo dõi: payload được sử dụng khi nào, trên host nào, đường dẫn file nơi nó được đặt trên mục tiêu, và liệu nó đã được dọn dẹp hay còn cần được dọn dẹp bởi khách hàng. File hash cũng được khuyến nghị để dễ dàng tra cứu từ phía khách hàng. Nên cung cấp thông tin này ngay cả khi ta đã xóa web shell, payload, hoặc công cụ.

### Tạo tài khoản / Thay đổi hệ thống

Nếu tạo tài khoản hoặc thay đổi cấu hình hệ thống, cần đảm bảo rằng những thay đổi này được theo dõi trong trường hợp không thể hoàn tác sau khi đánh giá kết thúc. Một số ví dụ bao gồm:

- Địa chỉ IP của host/hostname nơi thay đổi được thực hiện
- Dấu thời gian (timestamp) của thay đổi
- Mô tả về thay đổi
- Vị trí trên host nơi thay đổi được thực hiện
- Tên ứng dụng hoặc dịch vụ bị tác động
- Tên tài khoản (nếu tạo mới) và có thể cả mật khẩu trong trường hợp cần cung cấp lại

Điều hiển nhiên nhưng vẫn cần nhắc lại: để giữ tính chuyên nghiệp và tránh gây thù địch với đội hạ tầng của khách hàng, bạn cần có sự chấp thuận bằng văn bản từ khách hàng trước khi thực hiện các thay đổi hệ thống dạng này hoặc bất kỳ kiểm thử nào có thể ảnh hưởng đến sự ổn định hoặc khả năng sẵn sàng của hệ thống. Việc này thường được thống nhất trong buổi họp khởi động dự án (kickoff call) để xác định ngưỡng mà khách hàng có thể chấp nhận mà không cần được thông báo trước.

---

## Bằng chứng (Evidence)

Dù là loại đánh giá nào, khách hàng (thường) không quan tâm đến chuỗi khai thác (exploit chain) thú vị hay việc bạn "hạ gục" mạng của họ dễ dàng ra sao. Cuối cùng, họ trả tiền cho sản phẩm báo cáo — thứ cần truyền đạt rõ ràng các vấn đề được phát hiện cùng bằng chứng có thể dùng để xác minh và tái hiện lại. Không có bằng chứng rõ ràng, đội bảo mật nội bộ, quản trị viên hệ thống, lập trình viên,... sẽ gặp khó khăn trong việc tái hiện lại công việc của ta khi khắc phục lỗi, hoặc thậm chí hiểu được bản chất của vấn đề.

### Cần thu thập những gì

Mỗi phát hiện đều cần có bằng chứng đi kèm. Cũng nên thu thập bằng chứng cho cả những phép thử không thành công, phòng trường hợp khách hàng đặt câu hỏi về mức độ kỹ lưỡng. Nếu làm việc trên dòng lệnh, log Tmux có thể đủ làm bằng chứng để dán vào báo cáo dưới dạng output terminal thực tế, nhưng chúng có thể có định dạng rất xấu. Vì lý do đó, việc chụp lại output terminal cho các bước quan trọng và theo dõi riêng biệt cùng với các phát hiện là một ý tưởng hay. Với mọi thứ khác, nên chụp ảnh màn hình.

### Lưu trữ

Cũng như với cấu trúc ghi chép, nên xây dựng một khuôn khổ để tổ chức dữ liệu thu thập được trong quá trình đánh giá. Điều này có vẻ hơi thừa với các dự án nhỏ, nhưng nếu đang kiểm thử trong một môi trường lớn mà không có cách theo dõi có cấu trúc, ta sẽ dễ quên mất điều gì đó, vi phạm phạm vi thỏa thuận (rules of engagement), và có khả năng làm lại công việc nhiều lần — điều này rất tốn thời gian, đặc biệt với các dự án có giới hạn thời gian. Dưới đây là cấu trúc thư mục nền tảng được đề xuất, nhưng bạn có thể cần điều chỉnh tùy theo loại đánh giá hoặc hoàn cảnh riêng.

**Admin** – Phạm vi công việc (SoW) đang sử dụng, ghi chú từ cuộc họp khởi động dự án, báo cáo tiến độ, thông báo lỗ hổng, v.v.

**Deliverables** – Thư mục lưu các sản phẩm bàn giao trong quá trình thực hiện. Thường sẽ là báo cáo nhưng cũng có thể bao gồm các mục khác như bảng tính bổ sung hay slide, tùy theo yêu cầu cụ thể của khách hàng.

**Evidence** (Bằng chứng)
- *Findings* – Khuyến nghị tạo một thư mục cho mỗi phát hiện dự định đưa vào báo cáo, để giữ bằng chứng cho từng phát hiện trong một nơi tập trung, giúp việc ghép nối lại khi viết báo cáo dễ dàng hơn.
- *Scans*
  - *Vulnerability scans* – File export từ công cụ quét lỗ hổng (nếu áp dụng cho loại đánh giá) để lưu trữ.
  - *Service Enumeration* – File export từ các công cụ liệt kê dịch vụ trong môi trường mục tiêu như Nmap, Masscan, Rumble, v.v.
  - *Web* – File export từ các công cụ như ZAP hay Burp (state file), EyeWitness, Aquatone, v.v.
  - *AD Enumeration* – File JSON từ BloodHound, file CSV từ PowerView hoặc ADRecon, dữ liệu Ping Castle, log file Snaffler, log CrackMapExec, dữ liệu từ các công cụ Impacket, v.v.
- *Notes* – Thư mục để lưu ghi chú.
- *OSINT* – Output OSINT từ các công cụ như Intelx và Maltego không phù hợp để đưa vào tài liệu ghi chú.
- *Wireless* – Tùy chọn nếu kiểm thử không dây nằm trong phạm vi, dùng thư mục này cho output từ các công cụ kiểm thử wireless.
- *Logging output* – Output log từ Tmux, Metasploit, và các log khác không phù hợp với các thư mục con Scan ở trên.
- *Misc Files* – Web shell, payload, script tùy chỉnh, và các file khác được tạo ra trong quá trình đánh giá có liên quan đến dự án.

**Retest** – Thư mục tùy chọn nếu cần quay lại sau đánh giá ban đầu để kiểm tra lại các phát hiện trước đó. Có thể sao chép lại cấu trúc thư mục đã dùng trong đánh giá ban đầu vào thư mục này để tách riêng bằng chứng retest khỏi bằng chứng gốc.

Nên có sẵn script và mẹo để thiết lập nhanh khi bắt đầu một dự án đánh giá. Có thể dùng lệnh sau để tạo các thư mục và thư mục con, rồi điều chỉnh thêm tùy nhu cầu:

```shellsession
naruto3co@htb[/htb]$ mkdir -p ACME-IPT/{Admin,Deliverables,Evidence/{Findings,Scans/{Vuln,Service,Web,'AD Enumeration'},Notes,OSINT,Wireless,'Logging output','Misc Files'},Retest}
```

```shellsession
naruto3co@htb[/htb]$ tree ACME-IPT/

ACME-IPT/
├── Admin
├── Deliverables
├── Evidence
│   ├── Findings
│   ├── Logging output
│   ├── Misc Files
│   ├── Notes
│   ├── OSINT
│   ├── Scans
│   │   ├── AD Enumeration
│   │   ├── Service
│   │   ├── Vuln
│   │   └── Web
│   └── Wireless
└── Retest
```

Một tính năng hay của công cụ như Obsidian là ta có thể kết hợp cấu trúc thư mục và cấu trúc ghi chép. Nhờ vậy, có thể tương tác trực tiếp với ghi chú/thư mục từ dòng lệnh hoặc bên trong Obsidian. Dưới đây là cấu trúc thư mục tổng quát khi làm việc qua Obsidian:

<img width="1012" height="661" alt="image" src="https://github.com/user-attachments/assets/2fab4d4e-835f-4fe5-a5f1-25f90580c9fe" />

Đi sâu hơn, ta có thể thấy lợi ích của việc kết hợp cấu trúc ghi chép và thư mục. Trong một đánh giá thực tế, ta có thể thêm các trang/thư mục mới hoặc loại bỏ một số, tạo thêm một trang và một thư mục cho mỗi phát hiện, v.v.

<img width="1014" height="658" alt="image" src="https://github.com/user-attachments/assets/8437d34c-4c2e-46c5-b671-501ccd7f67eb" />


Xem nhanh cấu trúc thư mục, ta có thể thấy từng thư mục đã tạo trước đó, một số đã được điền các trang Markdown của Obsidian:

```shellsession
naruto3co@htb[/htb]$ tree

.
└── Inlanefreight Penetration Test
    ├── Admin
    ├── Deliverables
    ├── Evidence
    │   ├── Findings
    │   │   ├── H1 - Kerberoasting.md
    │   │   ├── H2 - ASREPRoasting.md
    │   │   ├── H3 - LLMNR&NBT-NS Response Spoofing.md
    │   │   └── H4 - Tomcat Manager Weak Credentials.md
    │   ├── Logging output
    │   ├── Misc files
    │   ├── Notes
    │   │   ├── 10. AD Enumeration Research.md
    │   │   ├── 11. Attack Path.md
    │   │   ├── 12. Findings.md
    │   │   ├── 1. Administrative Information.md
    │   │   ├── 2. Scoping Information.md
    │   │   ├── 3. Activity Log.md
    │   │   ├── 4. Payload Log.md
    │   │   ├── 5. OSINT Data.md
    │   │   ├── 6. Credentials.md
    │   │   ├── 7. Web Application Research.md
    │   │   ├── 8. Vulnerability Scan Research.md
    │   │   └── 9. Service Enumeration Research.md
    │   ├── OSINT
    │   ├── Scans
    │   │   ├── AD Enumeration
    │   │   ├── Service
    │   │   ├── Vuln
    │   │   └── Web
    │   └── Wireless
    └── Retest

16 directories, 16 files
```

> **Lưu ý:** Cấu trúc thư mục và ghi chép nêu trên là những gì hiệu quả với đội ngũ HTB trong sự nghiệp của họ, nhưng sẽ khác nhau tùy người và tùy dự án. Bạn được khuyến khích thử nghiệm cấu trúc này như một nền tảng cơ bản, xem nó phù hợp với mình ra sao, và dùng nó làm cơ sở để xây dựng phong cách riêng. Điều quan trọng là phải kỹ lưỡng và có tổ chức, và không có cách tiếp cận duy nhất nào cho việc này. Obsidian là một công cụ tuyệt vời, và định dạng này gọn gàng, dễ theo dõi, và dễ tái sử dụng cho từng dự án.

---

## Định dạng và Che thông tin nhạy cảm (Formatting and Redaction)

Thông tin đăng nhập và thông tin định danh cá nhân (PII) cần được che (redact) trong ảnh chụp màn hình, cũng như bất kỳ nội dung nào mang tính phản cảm về mặt đạo đức, chẳng hạn hình ảnh phản cảm hoặc ngôn từ tục tĩu. Có thể cân nhắc thêm:

- Thêm chú thích lên ảnh như mũi tên hoặc khung để làm nổi bật các mục quan trọng trong ảnh chụp, đặc biệt khi có nhiều nội dung trong ảnh (không nên làm việc này trong MS Word).
- Thêm viền tối thiểu quanh ảnh để nó nổi bật trên nền trắng của tài liệu.
- Cắt ảnh để chỉ hiển thị thông tin liên quan (ví dụ: thay vì chụp toàn màn hình, chỉ hiển thị một form đăng nhập cơ bản).
- Bao gồm thanh địa chỉ trình duyệt hoặc thông tin khác cho biết bạn đang kết nối tới URL hay host nào.

### Ảnh chụp màn hình (Screenshots)

Bất cứ khi nào có thể, nên ưu tiên dùng output dạng văn bản của terminal thay vì ảnh chụp màn hình terminal. Văn bản dễ che hơn, dễ tô đậm phần quan trọng (ví dụ: lệnh đã chạy tô màu xanh, phần output cần chú ý tô màu đỏ), thường trông gọn gàng hơn trong tài liệu, và giúp tránh tài liệu trở nên nặng nề, cồng kềnh khi có nhiều phát hiện. Cần cẩn thận không chỉnh sửa sai lệch output của terminal vì ta muốn thể hiện chính xác lệnh đã chạy và kết quả. Có thể rút gọn/cắt bớt phần output không cần thiết và đánh dấu phần đã loại bỏ bằng `<SNIP>`, nhưng tuyệt đối không được thay đổi output hay thêm những gì không có trong lệnh/output gốc. Việc dùng các hình ảnh dạng văn bản (text-based) cũng giúp khách hàng dễ copy/paste để tái hiện kết quả của bạn. Cũng quan trọng là văn bản nguồn bạn dán vào phải được loại bỏ hết định dạng trước khi đưa vào tài liệu Word. Nếu dán văn bản có định dạng nhúng, có thể sẽ dán nhầm các ký tự không phải UTF-8 (thường là dấu ngoặc kép hoặc dấu nháy đơn thay thế), khiến lệnh không chạy đúng khi khách hàng cố tái hiện lại.

Một cách phổ biến để che ảnh chụp màn hình là làm mờ hoặc pixelate bằng công cụ như Greenshot. Tuy nhiên, nghiên cứu cho thấy phương pháp này không hoàn toàn an toàn, và có khả năng cao dữ liệu gốc có thể được khôi phục lại bằng cách đảo ngược kỹ thuật pixelate/làm mờ đó — có thể thực hiện việc này bằng công cụ như Unredacter. Thay vào đó, nên tránh kỹ thuật này và dùng thanh đen (hoặc một hình khối đặc khác) để che phần văn bản cần ẩn. Nên chỉnh sửa trực tiếp lên ảnh chứ không chỉ thêm một hình khối trong MS Word, vì ai đó có quyền truy cập tài liệu có thể dễ dàng xóa nó đi. Ngoài ra, nếu bạn viết một bài blog hay nội dung công khai trên web với dữ liệu nhạy cảm đã được che, đừng dựa vào định dạng HTML/CSS để cố ẩn văn bản (ví dụ: chữ đen trên nền đen), vì điều này có thể dễ dàng bị lộ khi bôi đen văn bản hoặc xem tạm thời mã nguồn trang. Khi còn phân vân, hãy dùng output dạng console; nhưng nếu buộc phải dùng ảnh chụp terminal, hãy đảm bảo che thông tin đúng cách. Dưới đây là ví dụ về hai kỹ thuật:

**Làm mờ dữ liệu mật khẩu (Blurring Password Data)**

<img width="1417" height="205" alt="image" src="https://github.com/user-attachments/assets/b9944d5a-9c21-431e-a4d7-364b0e0dff7e" />


**Che mật khẩu bằng hình khối đặc (Blanking Out Password with Solid Shape)**

<img width="1417" height="205" alt="image" src="https://github.com/user-attachments/assets/cba3f6ec-778d-44fb-9a15-3b8c03200b4f" />


Cuối cùng, đây là một cách đề xuất để trình bày bằng chứng terminal trong tài liệu báo cáo. Ở đây, lệnh và output gốc được giữ nguyên nhưng được làm nổi bật cả phần lệnh lẫn phần output đáng chú ý (xác thực thành công).

<img width="976" height="113" alt="image" src="https://github.com/user-attachments/assets/f8c45106-cb69-400f-9cf3-b63ac80c16f6" />


Cách trình bày bằng chứng sẽ khác nhau tùy báo cáo. Có thể có tình huống không thể copy/paste output console, khi đó phải dựa vào ảnh chụp màn hình. Các mẹo ở đây nhằm cung cấp các lựa chọn để tạo ra một báo cáo gọn gàng nhưng vẫn chính xác, với mọi bằng chứng được trình bày đầy đủ.

### Terminal

Thông thường, thứ duy nhất cần che trong output terminal là thông tin đăng nhập (dù trong lệnh hay trong output của lệnh). Điều này bao gồm cả password hash. Với hash mật khẩu, thường chỉ cần cắt bỏ phần giữa và giữ lại 3-4 ký tự đầu và cuối để cho thấy đó thực sự là một hash. Với thông tin đăng nhập dạng plaintext hoặc bất kỳ nội dung dễ đọc nào khác cần được che, có thể thay bằng placeholder `<REDACTED>` hoặc `<PASSWORD REDACTED>`, hoặc tương tự.

Cũng nên cân nhắc tô màu (highlight) trong output terminal để làm nổi bật lệnh đã chạy và phần output đáng chú ý từ lệnh đó. Điều này giúp người đọc dễ dàng nhận ra các phần bằng chứng thiết yếu và biết cần tìm gì nếu họ muốn tự tái hiện lại. Nếu đang làm việc với một payload web phức tạp, sẽ khó để nhận ra payload trong một khối văn bản request đã URL-encode khổng lồ nếu không quen làm việc này thường xuyên. Nên tận dụng mọi cơ hội để làm báo cáo rõ ràng hơn cho người đọc — những người thường không có hiểu biết sâu về môi trường (đặc biệt từ góc nhìn của một pentester) như chúng ta có được vào cuối đợt đánh giá.

---

## Những gì không nên lưu trữ (What Not to Archive)

Khi bắt đầu một bài kiểm tra thâm nhập, khách hàng tin tưởng giao cho chúng ta quyền truy cập vào mạng của họ và yêu cầu "không gây hại" (do no harm) bất cứ khi nào có thể. Điều này nghĩa là không được làm sập bất kỳ host nào hay ảnh hưởng đến khả năng sẵn sàng của ứng dụng hoặc tài nguyên, không thay đổi mật khẩu (trừ khi được cho phép rõ ràng), không thực hiện các thay đổi cấu hình đáng kể hoặc khó đảo ngược, hoặc xem/xóa một số loại dữ liệu nhất định khỏi môi trường. Dữ liệu này có thể bao gồm PII chưa được che, thông tin có khả năng liên quan đến hình sự, bất cứ điều gì được xem là "có thể phải trình ra" (discoverable) về mặt pháp lý, v.v. Ví dụ, nếu bạn truy cập được một network share chứa dữ liệu nhạy cảm, tốt nhất chỉ nên chụp ảnh màn hình thư mục chứa các file đó thay vì mở từng file và chụp nội dung bên trong. Nếu các file thực sự nhạy cảm như bạn nghĩ, tên file cũng đủ để truyền đạt thông điệp mà không cần mở ra xem. Việc thu thập PII thực tế và trích xuất nó khỏi môi trường mục tiêu có thể kéo theo các nghĩa vụ tuân thủ đáng kể về việc lưu trữ và xử lý dữ liệu đó, như GDPR và các quy định tương tự, và có thể gây ra hàng loạt vấn đề cho công ty cũng như cho chính chúng ta.

---

## Bài tập Module (Module Exercises)

Đội ngũ HTB đã cung cấp sẵn một sổ tay Obsidian mẫu (điền một phần) trên máy Parrot Linux có thể khởi tạo ở cuối phần này. Bạn có thể truy cập bằng thông tin đăng nhập được cung cấp qua lệnh:

```shellsession
naruto3co@htb[/htb]$ xfreerdp /v:10.129.203.82 /u:htb-student /p:HTB_@cademy_stdnt!
```

Sau khi kết nối, bạn có thể mở Obsidian từ Desktop, duyệt qua sổ tay mẫu, và xem lại thông tin đã được điền sẵn một số dữ liệu mẫu dựa trên lab mà chúng ta sẽ thực hành sau này trong module này khi làm các bài tập tùy chọn (nhưng rất khuyến khích thực hiện!). Đội ngũ HTB cũng cung cấp một bản sao của sổ tay Obsidian này, có thể tải về từ mục "Resources" ở góc trên bên phải của bất kỳ phần nào trong module. Sau khi tải về và giải nén, bạn có thể mở nó bằng bản Obsidian cài local bằng cách chọn **Open folder as vault**.

---

## Tiếp theo (Onwards)

Giờ đây khi đã nắm được cấu trúc ghi chép và tổ chức thư mục, cũng như loại bằng chứng nào nên giữ và không nên giữ, và những gì cần log cho báo cáo, hãy cùng tìm hiểu về các loại báo cáo khác nhau mà khách hàng có thể yêu cầu tùy theo loại dự án.

---

## Câu hỏi (Connect to HTB)

**Câu hỏi 1:** Công cụ nào được đề cập trong phần này giúp việc ghi log một phiên làm việc dễ dàng hơn?
*(RDP tới máy với user "htb-student" và mật khẩu "HTB_@cademy_stdnt!")*

**Câu hỏi 2:** Steve đang tìm hiểu về công cụ giúp việc ghi log phiên làm việc dễ dàng hơn. Anh ấy nhắn tin nhờ bạn giúp, nói rằng muốn thử chia các pane theo chiều dọc. Bạn sẽ hướng dẫn anh ấy thế nào? *(Định dạng trả lời: [phím] + [phím] + [phím])*

**Bài tập tùy chọn:** Kết nối tới máy ảo kiểm thử bằng Xfreerdp, thử nghiệm với cấu trúc thư mục đánh giá và sổ tay Obsidian, và thử nghiệm với việc ghi log Tmux. Gõ DONE khi bạn đã hoàn thành.

---

*Tài liệu được dịch từ module "Notetaking & Organization" của Hack The Box Academy.*
