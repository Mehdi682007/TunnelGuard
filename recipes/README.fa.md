# الگوهای کلاینت

این فایل‌ها کانفیگ آماده اتصال نیستند. مقادیر YOUR_* و REPLACE_* را با مشخصات سرور خودتان جایگزین کنید؛ سپس فایل را از پسوند `.example` خارج کرده و با ابزار اعتبارسنجی نسخه نصب‌شده هسته بررسی کنید. این بسته سرور متناظر، UUID، کلید یا گواهی واقعی ایجاد نمی‌کند.

- `sing-box-reality.json.example`: ورودی محلی 11001، خروجی VLESS/REALITY. بعد از تکمیل، `sing-box check -c FILE` را اجرا کنید.
- `hysteria-client.yaml.example`: ورودی SOCKS محلی 11002 و بررسی گواهی فعال. fastOpen خاموش است تا شکست اتصال مقصد پیش از تأیید SOCKS قابل تشخیص باشد.
- `ssh_config.example`: alias برابر tg-backup. کلید میزبان باید قبلاً به شکل قابل اعتماد در known_hosts ثبت شده باشد؛ اسکریپت بررسی آن را دور نمی‌زند. پورت SOCKS را آداپتر SSH مدیر می‌سازد.

برای Backhaul و Rathole، خروجی فوروارد ساده معادل SOCKS نیست؛ یک پورت SOCKS/HTTP دوردست را از همان تانل عبور دهید. برای Parsa v3، لایه overlay و خروجی SOCKS باید مستقل آماده شوند. جزئیات در راهنمای چندلایه آمده است.

منابع قالب‌ها: [VLESS در sing-box](https://sing-box.sagernet.org/configuration/outbound/vless/)، [TLS و REALITY](https://sing-box.sagernet.org/configuration/shared/tls/)، [Hysteria client](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)، [SSH](https://man.openbsd.org/ssh.1).
