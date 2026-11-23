# 06 – Thu thập dữ liệu và gán nhãn

## 1. Mục tiêu dữ liệu

Mô hình cần học sự khác biệt hành vi traffic giữa các ứng dụng, không học nhầm đặc điểm của một phiên capture, một thiết bị hoặc một thời điểm duy nhất.

## 2. Thành phần một session

Một session nên có:
- PCAP;
- file labels (START/END hoặc event timeline);
- metadata session: session ID, batch, ngày giờ, thiết bị, OS, interface, subnet, app, phiên bản app nếu biết;
- ghi chú điều kiện mạng: Wi-Fi/Ethernet, VPN, DNS mode, người dùng/thiết bị khác có traffic nền không.

README cũ đề cập `tools/capture_session.py` tạo PCAP, labels JSONL và session JSON. Cần kiểm tra format thực tế của các file đầu ra.

## 3. Quy trình thu thập khuyến nghị

1. Chuẩn bị thiết bị và kiểm tra interface.
2. Đóng hoặc ghi nhận các ứng dụng không thuộc thí nghiệm.
3. Bắt đầu capture trước khi mở app.
4. Ghi nhãn START đúng lúc bắt đầu thao tác.
5. Thực hiện hành vi đại diện (ví dụ xem video, nghe nhạc, gọi họp), không chỉ mở app rồi để yên.
6. Ghi nhãn END sau khi dừng hoạt động.
7. Chờ một khoảng ngắn để quan sát traffic nền nếu cần.
8. Lặp lại nhiều session độc lập vào thời điểm khác nhau.
9. Kiểm tra PCAP và nhãn trước khi build dataset.

## 4. Nhiễu nhãn

Session labeling theo thời gian có thể gán nhãn sai nếu:
- hệ điều hành tự cập nhật;
- trình duyệt chạy nhiều tab/app;
- app phụ thuộc dịch vụ chung;
- app đã dừng nhưng connection vẫn còn;
- flow bắt đầu trước START hoặc kết thúc sau END;
- nhiều app chạy đồng thời.

Cần quy định rõ cách xử lý flow cắt qua biên nhãn. Có thể loại mẫu không đủ chắc chắn thay vì ép gán nhãn.

## 5. Nhãn nền

Các lớp `other-idle`, `other-web`, `other-update` phải có định nghĩa vận hành rõ ràng. Không dùng `other` như một nhãn gom mọi thứ nếu trong đó có nhiều hành vi khác nhau.

## 6. Số lượng session

Nhiều flow từ một PCAP không tương đương nhiều session độc lập. Để đánh giá generalization, cần thu nhiều phiên cho mỗi app:
- khác thời điểm;
- có thể khác thiết bị hoặc điều kiện mạng;
- cùng quy trình thao tác được ghi chép.

Không tuyên bố mô hình tổng quát hóa nếu một app chỉ có một session.

## 7. Data quality checklist

- [ ] PCAP mở được và có packet.
- [ ] Timestamp hợp lệ, đơn vị thống nhất.
- [ ] Interface/subnet/client được xác định.
- [ ] Nhãn START/END không chồng lấn ngoài dự kiến.
- [ ] Không có app không mong muốn chạy nền.
- [ ] Có metadata session.
- [ ] Kiểm tra phân bố flow/packet/bytes theo app.
- [ ] Loại session lỗi hoặc nhãn không chắc chắn.
- [ ] Lưu hash hoặc ID dataset version để tái lập.
