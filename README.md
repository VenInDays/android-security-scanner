# Android Security Scanner

App quét bảo mật Android - phát hiện virus, adware, spyware và theo dõi hoạt động mạng.

## Tính năng
- **mTim Network Tracking**: Theo dõi khi nào app sử dụng internet lần cuối (qua NetworkStatsManager)
- **Malware Scanner**: Quét phát hiện virus/adware/spyware bằng nhiều phương pháp
- **Permission Analysis**: Phân tích quyền nguy hiểm và kết hợp quyền đáng ngờ
- **Typo-squatting Detection**: Phát hiện tên gói giả mạo
- **Certificate Verification**: Kiểm tra chữ ký số
- **Metadata Analysis**: Phát hiện Xposed modules, ad SDK đáng ngờ

## Yêu cầu
- Android 8.0+ (API 26+)
- Quyền Usage Access (PACKAGE_USAGE_STATS)

## Build
APK được tự động build qua GitHub Actions và upload lên Releases.

## GitHub Actions
Khi push code lên branch `main`, workflow sẽ:
1. Build debug APK
2. Build release APK
3. Upload APK lên GitHub Releases
