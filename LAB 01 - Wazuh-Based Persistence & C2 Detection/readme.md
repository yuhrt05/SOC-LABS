# 🛡️ LAB 01 – Wazuh-Based Persistence & C2 Detection

## 📌 Mục tiêu
Lab này mô phỏng kịch bản tấn công trong đó attacker thiết lập:

- **Persistence** – Duy trì quyền truy cập lâu dài trên hệ thống.  
- **Command & Control (C2)** – Duy trì kênh điều khiển và nhận lệnh từ máy chủ bên ngoài.

**Nhiệm vụ của SOC Analyst:**
- Phát hiện dấu hiệu Persistence trên Windows endpoint.  
- Xác định hoạt động/lưu lượng C2 bất thường.  
- Phân tích log và tạo cảnh báo trong Wazuh SIEM.  

## 🛠 Môi trường Lab
- **Wazuh Server** – Thu thập log từ các agent và phân tích.  
- **Windows Agent** – Cài Sysmon + Wazuh Agent để giám sát tiến trình, registry và kết nối mạng.  
- **Attacker**– Tạo môi trường C2.  
- **Network** – Cho phép lưu lượng từ Windows → Kali để giả lập kênh C2.  

## 📊 Kết quả mong đợi
Wazuh phát hiện được:
- Tạo Registry Key mới bất thường (**Persistence**).  
- Tiến trình tạo kết nối outbound đến IP/domain đáng ngờ.  
- Mẫu C2 liên tục beacon tới cùng một IP/domain.  
- Sinh cảnh báo trực quan trên dashboard Wazuh.  

Ngoài ra, SOC Analyst có thể:
- Xuất báo cáo ngắn gọn về kỹ thuật tấn công, IoC, và khuyến nghị phòng thủ.  

