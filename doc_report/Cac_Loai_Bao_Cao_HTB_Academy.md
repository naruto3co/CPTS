# Các Loại Báo Cáo (Types of Reports) — Hack The Box Academy

Cấu trúc báo cáo của chúng ta sẽ hơi khác nhau tùy theo loại đánh giá (assessment) được giao thực hiện. Trong module này, ta sẽ tập trung chủ yếu vào báo cáo Internal Penetration Test (kiểm thử xâm nhập nội bộ) trong trường hợp tester đã chiếm được quyền kiểm soát domain Active Directory (AD) trong quá trình kiểm thử. Báo cáo mẫu sẽ minh họa các thành phần điển hình của một báo cáo Internal Penetration Test. Ngoài ra, ta cũng sẽ đề cập đến một số khía cạnh của các loại báo cáo khác (ví dụ như các phụ lục bổ sung có thể xuất hiện trong báo cáo External Penetration Test). Việc một báo cáo External Penetration Test dẫn đến xâm nhập nội bộ, kèm theo attack chain và các yếu tố khác mà ta sẽ đề cập, là điều không hiếm gặp.

Điểm khác biệt chính trong lab của chúng ta là sẽ không bao gồm dữ liệu OSINT/thông tin công khai như địa chỉ email, subdomain, thông tin đăng nhập bị lộ trong các vụ rò rỉ dữ liệu (breach dump), thông tin đăng ký/sở hữu domain, v.v., vì ta không kiểm thử một công ty thực có sự hiện diện trên Internet. Dù có một số công cụ "kỳ cựu" vẫn còn giá trị như Have I Been Pwned, Shodan, và Intelx, các công cụ OSINT nhìn chung rất hay thay đổi, nên đến thời điểm khóa học này được phát hành, công cụ hoặc nguồn tốt nhất để thu thập thông tin đó có thể đã khác. Thay vào đó, tài liệu liệt kê một số loại thông tin thường được nhắm tới trong một bài kiểm thử xâm nhập, và để người đọc tự tìm hiểu công cụ/API nào cho kết quả tốt nhất. Luôn nên chạy nhiều công cụ khác nhau để so sánh kết quả, thay vì chỉ phụ thuộc vào một công cụ duy nhất.

Các loại thông tin công khai và bản ghi sở hữu domain:
- Địa chỉ Email — có thể dùng để kiểm tra xem có bị lộ trong breach hay dùng Google Dork để tìm trên các trang như Pastebin
- Subdomain
- Nhà cung cấp bên thứ ba (Third-party vendors)
- Các domain tương tự
- Tài nguyên cloud công khai

Những loại thu thập thông tin này được đề cập trong các module khác như *Information Gathering - Web Edition*, *OSINT: Corporate Recon*, và *Footprinting*, nên nằm ngoài phạm vi của module này.

## Sự Khác Biệt Giữa Các Loại Đánh Giá

Trước khi đi qua các loại báo cáo và các thành phần của báo cáo Penetration Test, hãy cùng định nghĩa một số loại đánh giá chính.

### Vulnerability Assessment (Đánh giá lỗ hổng)

Vulnerability assessment là việc chạy quét tự động trên một môi trường để liệt kê các lỗ hổng. Có thể quét có xác thực (authenticated) hoặc không xác thực (unauthenticated). Không có khai thác (exploitation) nào được thực hiện, nhưng thường sẽ cần xác thực lại kết quả từ scanner để báo cáo cho khách hàng biết đâu là vấn đề thật, đâu là false positive. Việc xác thực có thể bao gồm kiểm tra thêm để xác nhận một phiên bản dễ bị tấn công đang được sử dụng, hoặc một cấu hình sai đang tồn tại — nhưng mục tiêu không phải là chiếm quyền truy cập ban đầu (foothold) hay di chuyển ngang/dọc trong hệ thống. Một số khách hàng thậm chí chỉ yêu cầu kết quả quét mà không cần xác thực.

**Nội bộ và bên ngoài (Internal vs External):** Quét bên ngoài (external scan) được thực hiện từ góc nhìn của một người dùng ẩn danh trên Internet, nhắm vào hệ thống công khai của tổ chức. Quét nội bộ (internal scan) được thực hiện từ góc nhìn bên trong mạng nội bộ, phía sau tường lửa. Có thể mô phỏng góc nhìn của người dùng ẩn danh trong mạng nội bộ, một server bị xâm nhập, hoặc nhiều kịch bản khác. Khách hàng cũng có thể yêu cầu quét nội bộ có sử dụng thông tin đăng nhập (credentials), giúp phát hiện nhiều lỗ hổng hơn nhưng cũng cho kết quả chính xác và cụ thể hơn (ít false positive hơn).

**Nội dung báo cáo:** Báo cáo loại này thường tập trung vào các chủ đề quan sát được từ kết quả quét, nêu bật số lượng lỗ hổng và mức độ nghiêm trọng. Vì các bản quét này có thể tạo ra rất nhiều dữ liệu, việc xác định các mẫu hình (pattern) và ánh xạ chúng vào các thiếu sót quy trình là rất quan trọng để tránh gây quá tải thông tin.

### Penetration Testing (Kiểm thử xâm nhập)

Penetration testing đi xa hơn việc quét tự động, có thể tận dụng dữ liệu từ vulnerability scan để định hướng khai thác. Cũng giống như vulnerability scan, có thể thực hiện từ góc nhìn nội bộ hoặc bên ngoài. Tùy loại pentest (ví dụ: kiểm thử né tránh - evasive test), có thể sẽ không thực hiện bất kỳ bước quét lỗ hổng nào.

Một bài pentest có thể được thực hiện theo nhiều góc nhìn khác nhau:
- **Black box**: chỉ biết tên công ty (đối với external) hoặc có một kết nối mạng (đối với internal), không có thêm thông tin nào khác.
- **Grey box**: được cung cấp dải IP/CIDR nằm trong phạm vi.
- **White box**: được cung cấp thông tin đăng nhập, mã nguồn, cấu hình, v.v.

Kiểm thử có thể thực hiện với mức độ "né tránh" (evasion) bằng 0 để cố gắng phát hiện càng nhiều lỗ hổng càng tốt, hoặc theo kiểu lai (hybrid evasive) — bắt đầu né tránh rồi dần "gây tiếng ồn" hơn để xem đội an ninh/hệ thống giám sát nội bộ phát hiện và chặn ở mức độ nào. Thông thường, khi bị phát hiện trong loại đánh giá này, khách hàng sẽ yêu cầu chuyển sang kiểm thử không né tránh cho phần còn lại. Đây là loại đánh giá phù hợp để đề xuất cho khách hàng đã có một số biện pháp phòng thủ nhưng chưa thực sự trưởng thành về an ninh — giúp lộ ra các lỗ hổng phòng thủ và nơi cần tập trung cải thiện khả năng phát hiện/ngăn chặn. Với khách hàng có mức độ trưởng thành cao hơn, loại đánh giá này là bài kiểm tra tốt cho hệ thống phòng thủ và quy trình nội bộ, đảm bảo mọi bên thực hiện đúng vai trò khi có tấn công thật xảy ra.

Cuối cùng, có thể được yêu cầu thực hiện kiểm thử né tránh xuyên suốt (evasive testing). Ở loại này, tester cố gắng không bị phát hiện càng lâu càng tốt và xem có thể đạt được mức truy cập nào trong khi hoạt động âm thầm. Điều này mô phỏng một kẻ tấn công có trình độ cao hơn. Tuy nhiên, loại đánh giá này thường bị giới hạn về thời gian — điều mà kẻ tấn công thực sự không gặp phải. Khách hàng cũng có thể chọn mô phỏng đối thủ dài hạn (adversary simulation), kéo dài nhiều tháng, chỉ một số ít nhân viên công ty biết về việc đánh giá, và thậm chí không ai biết chính xác ngày/giờ bắt đầu. Loại đánh giá này phù hợp với các tổ chức có mức độ trưởng thành an ninh cao và đòi hỏi kỹ năng khác biệt so với một pentester mạng/ứng dụng truyền thống.

**Nội bộ và bên ngoài:** Tương tự vulnerability scanning, external penetration test thường được thực hiện từ góc nhìn kẻ tấn công ẩn danh trên Internet, có thể tận dụng dữ liệu OSINT/thông tin công khai để cố gắng truy cập dữ liệu nhạy cảm qua ứng dụng hoặc mạng nội bộ bằng cách tấn công các host hướng ra Internet. Internal penetration test có thể thực hiện với vai trò người dùng ẩn danh hoặc đã xác thực trong mạng nội bộ, thường nhằm tìm càng nhiều lỗ hổng càng tốt để có được foothold, leo thang đặc quyền ngang/dọc, di chuyển ngang và xâm nhập mạng nội bộ (thường là môi trường Active Directory của khách hàng).

## Các Đánh Giá Liên Ngành (Inter-Disciplinary Assessments)

Một số đánh giá cần sự tham gia của nhiều người có kỹ năng khác nhau bổ trợ cho nhau. Dù phức tạp hơn về mặt hậu cần, những đánh giá này thường mang tính hợp tác cao hơn giữa đội tư vấn và khách hàng, tạo thêm giá trị và sự tin tưởng cho mối quan hệ. Một số ví dụ:

**Đánh giá kiểu Purple Team:** Là nỗ lực kết hợp giữa đội blue và red, phổ biến nhất là giữa pentester và người xử lý sự cố (incident responder). Ý tưởng chung là pentester mô phỏng một mối đe dọa cụ thể, còn incident responder làm việc cùng đội blue nội bộ để xem xét bộ công cụ hiện có, xác định xem cảnh báo đã được cấu hình đúng hay cần điều chỉnh để phát hiện chính xác.

**Kiểm thử xâm nhập tập trung vào Cloud:** Dù có nhiều điểm trùng lặp với pentest thông thường, đánh giá tập trung vào cloud sẽ hưởng lợi từ kiến thức của người có nền tảng về kiến trúc và quản trị cloud. Đôi khi chỉ đơn giản là giúp pentester hiểu rõ những gì có thể bị lạm dụng từ một thông tin cụ thể được phát hiện (như secret hay key nào đó). Khi hạ tầng trở nên phức tạp hơn như container và ứng dụng serverless, cách tiếp cận kiểm thử các tài nguyên này đòi hỏi kiến thức rất cụ thể, có thể cần phương pháp luận và bộ công cụ hoàn toàn khác. Vì cách báo cáo cho loại đánh giá này khá tương đồng với pentest thông thường, phần này chỉ được nhắc đến để tham khảo; chi tiết kỹ thuật kiểm thử các tài nguyên đặc thù này nằm ngoài phạm vi khóa học.

**Kiểm thử IoT toàn diện:** Nền tảng IoT thường có ba thành phần chính: mạng, cloud, và ứng dụng. Có những người chuyên sâu ở từng mảng này, khi kết hợp lại sẽ mang đến đánh giá toàn diện hơn nhiều so với việc chỉ dựa vào một người có kiến thức cơ bản ở mỗi lĩnh vực. Một thành phần khác có thể cần kiểm thử là lớp phần cứng (hardware layer), được đề cập bên dưới. Tương tự kiểm thử cloud, một số khía cạnh của việc kiểm thử này đòi hỏi kỹ năng chuyên biệt nằm ngoài phạm vi khóa học, nhưng cấu trúc báo cáo pentest tiêu chuẩn vẫn phù hợp để trình bày loại dữ liệu này.

**Kiểm thử xâm nhập ứng dụng Web:** Tùy phạm vi, loại đánh giá này cũng có thể được xem là liên ngành. Một số đánh giá ứng dụng chỉ tập trung xác định và xác thực lỗ hổng trong ứng dụng với kiểm thử có xác thực/theo vai trò (role-based), không quan tâm đến server bên dưới. Số khác có thể muốn kiểm thử cả ứng dụng lẫn hạ tầng, với mục tiêu xâm nhập ban đầu qua chính ứng dụng web (cũng có thể theo góc nhìn xác thực/theo vai trò), sau đó cố gắng vượt ra khỏi ứng dụng để xem còn host/hệ thống nào phía sau có thể bị xâm nhập. Loại đánh giá thứ hai này sẽ hưởng lợi từ người có nền tảng phát triển/kiểm thử ứng dụng cho giai đoạn xâm nhập ban đầu, sau đó là một pentester tập trung vào mạng để "sống nhờ vào tài nguyên có sẵn" (live off the land) và di chuyển hoặc leo thang đặc quyền qua Active Directory hay các phương thức khác ngoài bản thân ứng dụng.

**Kiểm thử xâm nhập phần cứng (Hardware):** Loại kiểm thử này thường thực hiện trên các thiết bị IoT, nhưng cũng có thể mở rộng sang kiểm thử an ninh vật lý của laptop do khách hàng gửi, hoặc kiosk/ATM tại chỗ. Mỗi khách hàng sẽ có mức độ chấp nhận khác nhau về độ sâu của kiểm thử, vì vậy cần thiết lập rõ quy tắc thực hiện (rules of engagement) trước khi bắt đầu, đặc biệt với các kiểm thử mang tính phá hủy. Nếu khách hàng mong muốn nhận lại thiết bị nguyên vẹn và hoạt động bình thường, thường không nên thử tháo chip khỏi bo mạch hay các kiểu tấn công tương tự.

## Báo Cáo Nháp (Draft Report)

Ngày càng phổ biến việc khách hàng mong muốn có sự trao đổi và đóng góp ý kiến vào báo cáo. Điều này có thể ở nhiều hình thức: thêm bình luận về cách họ dự định xử lý từng phát hiện (management response), điều chỉnh ngôn từ có thể gây khó chịu, hoặc sắp xếp lại nội dung theo ý họ. Vì vậy, tốt nhất nên gửi báo cáo nháp trước, cho khách hàng thời gian tự xem xét, sau đó bố trí một buổi trao đổi để họ đặt câu hỏi, làm rõ, hoặc chia sẻ mong muốn của mình. Khách hàng chi trả cho sản phẩm cuối cùng là báo cáo, nên cần đảm bảo nó đầy đủ và có giá trị nhất có thể đối với họ. Một số khách hàng sẽ không góp ý gì, số khác lại yêu cầu thay đổi/bổ sung đáng kể để phù hợp với nhu cầu — có thể để trình lên hội đồng quản trị xin thêm ngân sách, hoặc dùng báo cáo làm đầu vào cho lộ trình an ninh nhằm khắc phục và củng cố tình hình bảo mật.

## Báo Cáo Chính Thức (Final Report)

Thông thường, sau khi xem xét báo cáo cùng khách hàng và xác nhận họ hài lòng, ta có thể phát hành báo cáo chính thức với các chỉnh sửa cần thiết. Việc này có thể trông có vẻ rườm rà, nhưng nhiều tổ chức kiểm toán sẽ không chấp nhận báo cáo nháp để đáp ứng nghĩa vụ tuân thủ, nên đây là bước quan trọng đối với khách hàng.

## Báo Cáo Sau Khắc Phục (Post-Remediation Report)

Cũng phổ biến việc khách hàng yêu cầu kiểm tra lại các phát hiện ban đầu sau khi họ đã có cơ hội khắc phục. Đây gần như là bắt buộc đối với các tổ chức phải tuân thủ tiêu chuẩn như PCI. Không nên thực hiện lại toàn bộ đánh giá ở giai đoạn này, mà chỉ nên tập trung kiểm tra lại đúng các phát hiện và các host bị ảnh hưởng từ đánh giá ban đầu. Cũng cần đặt giới hạn thời gian cho việc kiểm tra khắc phục sau đánh giá ban đầu. Một số vấn đề có thể xảy ra nếu không làm vậy:

- Nếu khách hàng yêu cầu kiểm tra khắc phục sau vài tháng hoặc hơn một năm, môi trường có thể đã thay đổi quá nhiều để có thể so sánh "táo với táo".
- Nếu kiểm tra toàn bộ môi trường để tìm host mới bị ảnh hưởng bởi một phát hiện, có thể phát hiện thêm host mới và rơi vào vòng lặp kiểm tra khắc phục vô tận.
- Nếu chạy lại các bản quét quy mô lớn như vulnerability scan, khả năng cao sẽ tìm thấy những vấn đề chưa từng có trước đó, khiến phạm vi công việc vượt tầm kiểm soát.
- Nếu khách hàng gặp vấn đề với tính chất "chụp nhanh" (snapshot) của loại kiểm thử này, có thể đề xuất công cụ Breach and Attack Simulation (BAS) để chạy định kỳ các kịch bản đó, đảm bảo vấn đề không tái diễn.

Nếu bất kỳ tình huống nào ở trên xảy ra, nên chuẩn bị tinh thần đối mặt với sự soi xét kỹ hơn về mức độ nghiêm trọng, hoặc áp lực chỉnh sửa những thứ không nên chỉnh sửa để "giúp" khách hàng. Trong các tình huống này, phản hồi cần được xây dựng cẩn thận: vừa rõ ràng rằng sẽ không vượt qua ranh giới đạo đức (nhưng cần cẩn trọng để không ngụ ý rằng khách hàng đang cố tình yêu cầu điều gì đó thiếu trung thực), vừa đồng cảm với hoàn cảnh của họ và đưa ra hướng giải quyết. Ví dụ, nếu mối lo của họ là phải hoàn thành yêu cầu của kiểm toán viên trong thời gian không đủ, có thể họ chưa biết rằng nhiều kiểm toán viên chấp nhận một kế hoạch khắc phục được ghi chép đầy đủ với thời hạn hợp lý (kèm lý do vì sao không thể hoàn thành sớm hơn), thay vì phải khắc phục và đóng phát hiện ngay trong kỳ kiểm tra. Cách này giúp giữ được sự chính trực, khiến khách hàng cảm nhận được sự quan tâm chân thành, và cho họ một lối đi mà không phải "lật ngược" mọi thứ để đáp ứng.

Một cách tiếp cận là coi đây như một đánh giá hoàn toàn mới trong các tình huống này. Nếu khách hàng không đồng ý, thì nên chỉ kiểm tra lại các phát hiện từ báo cáo gốc, đồng thời ghi chú rõ trong báo cáo khoảng thời gian đã trôi qua kể từ đánh giá ban đầu — rằng đây chỉ là một kiểm tra tại một thời điểm nhất định để xác nhận liệu CHỈ những lỗ hổng đã báo cáo trước đó có còn ảnh hưởng đến (các) host ban đầu hay không, và rằng môi trường của khách hàng nhiều khả năng đã thay đổi đáng kể, trong khi một đánh giá mới chưa được thực hiện.

Về cách trình bày báo cáo, một số người thích cập nhật báo cáo gốc bằng cách gắn trạng thái cho từng host bị ảnh hưởng trong mỗi phát hiện (ví dụ: đã khắc phục, chưa khắc phục, khắc phục một phần...), trong khi số khác lại thích phát hành một báo cáo hoàn toàn mới có thêm nội dung so sánh và bản tóm tắt điều hành (executive summary) đã cập nhật.

## Báo Cáo Chứng Nhận (Attestation Report)

Một số khách hàng sẽ yêu cầu Thư Chứng Nhận (Attestation Letter) hoặc Báo Cáo Chứng Nhận (Attestation Report) phù hợp để gửi cho nhà cung cấp hoặc khách hàng của họ, những bên cần bằng chứng rằng họ đã thực hiện kiểm thử xâm nhập. Điểm khác biệt lớn nhất là khách hàng sẽ không muốn giao chi tiết kỹ thuật của các phát hiện, thông tin đăng nhập hay các thông tin bí mật khác cho bên thứ ba. Tài liệu này được rút gọn từ báo cáo đầy đủ, chỉ tập trung vào số lượng phát hiện, phương pháp thực hiện, và nhận xét chung về môi trường. Tài liệu này thường chỉ dài một hoặc hai trang.

## Các Sản Phẩm Bàn Giao Khác (Other Deliverables)

**Slide Deck (Bộ slide thuyết trình):** Có thể được yêu cầu chuẩn bị một bài thuyết trình cho nhiều cấp độ khán giả khác nhau — kỹ thuật hoặc điều hành cấp cao. Ngôn ngữ và trọng tâm nên khác biệt rõ giữa bản trình bày cho ban điều hành và phần chi tiết kỹ thuật trong báo cáo. Chỉ đưa biểu đồ và số liệu sẽ khiến khán giả buồn ngủ, nên tốt nhất là chuẩn bị sẵn vài câu chuyện thực tế hoặc sự kiện thời sự gần đây liên quan đến một vector tấn công hoặc sự cố cụ thể — càng tốt hơn nếu câu chuyện đó thuộc cùng ngành với khách hàng. Mục đích không phải để gieo rắc nỗi sợ hãi, và cần cẩn trọng để không trình bày theo hướng đó, nhưng nó sẽ giúp giữ sự chú ý của khán giả, khiến rủi ro trở nên gần gũi hơn để tối đa hóa khả năng họ hành động.

**Bảng tính các phát hiện (Spreadsheet of Findings):** Khá dễ hiểu — đây là toàn bộ các trường thông tin trong các phát hiện của báo cáo, nhưng được trình bày dạng bảng để khách hàng dễ dàng sắp xếp và thao tác dữ liệu hơn. Điều này cũng có thể giúp họ nhập các phát hiện vào hệ thống ticket để theo dõi nội bộ. Tài liệu này không nên bao gồm executive summary hay các đoạn tường thuật. Lý tưởng nhất là biết cách sử dụng pivot table để tạo ra các phân tích thú vị mà khách hàng có thể quan tâm. Mục tiêu hữu ích nhất là sắp xếp các phát hiện theo mức độ nghiêm trọng hoặc danh mục để giúp ưu tiên khắc phục.

## Thông Báo Lỗ Hổng (Vulnerability Notifications)

Đôi khi trong quá trình đánh giá, ta sẽ phát hiện một lỗ hổng nghiêm trọng cần phải dừng công việc để thông báo ngay cho khách hàng, để họ quyết định có cần vá khẩn cấp hay chờ đến khi kết thúc đánh giá.

**Khi nào nên soạn thông báo:** Tối thiểu, việc này nên được thực hiện đối với bất kỳ phát hiện nào có thể khai thác trực tiếp, tiếp xúc với Internet, và dẫn đến thực thi mã từ xa không cần xác thực hoặc lộ dữ liệu nhạy cảm, hoặc lợi dụng thông tin đăng nhập yếu/mặc định cho cùng mục đích. Ngoài ra, kỳ vọng nên được thiết lập trong quá trình khởi động dự án (project kickoff). Một số khách hàng muốn tất cả các phát hiện mức cao và nghiêm trọng được báo cáo ngoài luồng (out-of-band) bất kể nội bộ hay bên ngoài; một số khác cũng cần cả mức trung bình. Tốt nhất nên tự đặt ra một tiêu chuẩn cơ bản, thông báo cho khách hàng biết điều gì sẽ xảy ra, và để họ yêu cầu điều chỉnh quy trình nếu cần.

**Nội dung:** Do tính chất của các thông báo này, cần hạn chế phần nội dung thừa (fluff) để đội kỹ thuật có thể đi thẳng vào chi tiết và bắt tay khắc phục ngay. Vì vậy, tốt nhất nên giới hạn nội dung ở mức thông tin kỹ thuật thường có trong phần chi tiết phát hiện, kèm bằng chứng từ công cụ (tool-based evidence) để khách hàng có thể tái hiện lại nhanh chóng nếu cần.

## Tổng Hợp Lại

Sau khi đã đi qua các loại đánh giá và các loại báo cáo có thể cần tạo ra cho khách hàng, phần tiếp theo sẽ nói về các thành phần của một báo cáo.

---

*Tài liệu gốc: [Types of Reports | Hack The Box Academy](https://academy.hackthebox.com/app/module/162/section/1538)*
