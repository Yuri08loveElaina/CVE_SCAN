## cách sử dụng ## 
## 1. Thay đổi Discord Webhook URL ##
Trong phần cấu hình đầu script:

CONFIG = {
    ...
    "discord": {
        "enabled": True,
        "webhook_url": "https://discord.com/api/webhooks/your_webhook_here"
    },
    ...
}
Bạn chỉ cần thay "your_webhook_here" bằng Webhook URL Discord thật của bạn.

Cách lấy webhook Discord:

Vào Discord server → Cài đặt kênh → Tích hợp → Webhooks → Tạo webhook mới
Copy URL webhook và dán vào webhook_url
## 2. Thay đổi NVD Bulk Data URL ##
Mặc định URL lấy dữ liệu CVE gần nhất là:

"nvd_bulk_url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
Nếu bạn muốn tải toàn bộ dữ liệu CVE (bulk toàn bộ năm hoặc nhiều năm), bạn có thể thay đổi URL thành (ví dụ 2024):

NVD bulk full year JSON feed:
https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz
Bạn chỉ cần thay nvd_bulk_url thành link mong muốn, ví dụ:

"nvd_bulk_url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz",
## 3. Thay đổi Cấu hình Email (SMTP) ##
Phần config email nằm trong:

"email": {
    "enabled": True,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "your_email@gmail.com",
    "password": "your_app_password",
    "from_addr": "your_email@gmail.com",
    "to_addrs": ["alert_receiver@example.com"]
},
Bạn cần chỉnh sửa các trường như:

"smtp_server" và "smtp_port": với Gmail là smtp.gmail.com và 587 (TLS)
"username": email của bạn dùng để gửi mail
"password": mật khẩu ứng dụng (App Password) cho email (để bảo mật, không dùng mật khẩu chính)
"from_addr": email gửi đi, thường giống username
"to_addrs": danh sách email nhận cảnh báo (có thể nhiều địa chỉ)
Ví dụ config hoàn chỉnh:
CONFIG = {
    "targets": ["192.168.1.10", "test.example.com"],
    "email": {
        "enabled": True,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "myemail@gmail.com",
        "password": "abcd1234appassword",
        "from_addr": "myemail@gmail.com",
        "to_addrs": ["admin@example.com", "secteam@example.com"]
    },
    "discord": {
        "enabled": True,
        "webhook_url": "https://discord.com/api/webhooks/123456789012345678/abcdefgHIJKLMN_opqrstUVWXYZ"
    },
    "nvd_bulk_url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz",
    "log_file": "exploit_log.json",
    "github_token": None
}
