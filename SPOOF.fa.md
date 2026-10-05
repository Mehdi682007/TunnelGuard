# نصب خودکار Spoof — نسخه ۲.۲، آزمایشی

[English](SPOOF.md) · [نصب سه مسیر معمولی](DEPLOY.fa.md)

دیگر لازم نیست هسته Spoof را جداگانه نصب کنید. نصاب **Parsa spoof-tunnel v3.1.0-beta.0** و **sing-box 1.14.2** را با بررسی SHA256 دانلود می‌کند، تنظیمات دو سمت را می‌سازد و سرویس‌ها را راه می‌اندازد.

مسیر اتصال: برنامه ← SOCKS نگهبان ← Hysteria2 رمز‌شده ← حامل Spoof ← Hysteria2 سمت خارج ← مقصد. حامل Parsa به‌تنهایی رمزنگاری و SOCKS ندارد؛ نصاب این دو بخش را نیز آماده می‌کند. این قابلیت بر پایه نسخه بتای هسته [Parsa](https://github.com/ParsaKSH/spoof-tunnel/tree/v3.1.0-beta.0) است و آزمایشی محسوب می‌شود.

## پیش‌نیاز

Ubuntu 24.04، معماری amd64 یا arm64، Python 3.11+ و systemd لازم است. IP واقعی دو سرور و IP مبدأ مجاز برای هر سمت را باید مشخص کنید. ابزار IP مناسب پیدا نمی‌کند و شبکه‌های دیگر را اسکن نمی‌کند. هر دو میزبان باید امکان ارسال با مبدأ انتخاب‌شده داشته باشند؛ نصب نرم‌افزار نمی‌تواند محدودیت شبکه میزبان را رفع کند.

در پوشه مخزن روی هر دو سرور `git pull --ff-only` بزنید و پیش‌نیازها را نصب کنید:

```bash
sudo apt update
sudo apt install -y python3 curl openssl ca-certificates iproute2
```

## روی سرور خارج

هر چهار IP زیر فقط مثال مستندات‌اند؛ IPهای واقعی و مجاز خودتان را جایگزین کنید:

```bash
sudo python3 deploy.py spoof-server \
  --address 203.0.113.10 --client-address 198.51.100.20 \
  --server-source 192.0.2.10 --client-source 192.0.2.20 \
  --uplink tcp --downlink udp \
  --output /root/deployment-spoof-server --apply
```

- `address`: IP واقعی سرور خارج؛ `client-address`: IP واقعی سرور ایران.
- `server-source`: مبدأ انتخاب‌شده بسته‌های خارج به ایران.
- `client-source`: مبدأ انتخاب‌شده بسته‌های ایران به خارج.
- `uplink`: حامل ایران به خارج؛ `downlink`: حامل خارج به ایران. هرکدام TCP یا UDP انتخاب می‌شوند.

پورت‌های پیش‌فرض: دریافت خارج **19443**، دریافت ایران **19444**، لایه داخلی سرور **19445/UDP**، پل داخلی ایران **19446/UDP** و SOCKS ایران **11004/TCP**. برای تغییرشان به‌ترتیب از `--server-port`، `--client-port`، `--overlay-port`، `--bridge-port` و `--socks-port` استفاده کنید. مقادیر به فایل جفت‌سازی منتقل می‌شوند.

## روی سرور ایران

فایل `/root/deployment-spoof-server/pairing.json` را با SSH/SCP امن به سرور ایران منتقل کنید و نام آن را مثلاً `/root/pairing-spoof.json` بگذارید. این فایل رمز دارد؛ آن را منتشر نکنید و بررسی کلید میزبان SSH را خاموش نکنید.

```bash
sudo python3 deploy.py spoof-client --bundle /root/pairing-spoof.json \
  --output /root/deployment-spoof-client --apply
```

اگر نصب خودکار قبلی TunnelGuard در `/opt/tunnelguard-node/client/config.json` موجود باشد، مسیر **Spoof** خودکار به مسیرها و پروفایل‌های **All و Emergency** اضافه می‌شود. سایر مسیرها و پروفایل‌ها حفظ می‌شوند؛ از فایل اصلی پشتیبان گرفته می‌شود و سرویس نگهبان دوباره شروع می‌شود. این راه‌اندازی مجدد اتصال‌های جاری درگاه را قطع می‌کند. اگر مسیر هم‌نام یا هم‌آدرس از قبل موجود باشد، نصاب آن را بازنویسی نمی‌کند.

اگر نصب قبلی وجود نداشته باشد، یک نگهبان مستقل با مسیر Spoof نصب می‌شود. درگاه `127.0.0.1:1088` و داشبورد `127.0.0.1:8787` است. نصب‌های سفارشی در مسیرهای دیگر خودکار تغییر نمی‌کنند؛ اگر پورت اشغال باشد نصب متوقف می‌شود. پروفایل فعال قبلی حفظ می‌شود؛ برای استفاده از Spoof، All یا Emergency را انتخاب کنید.

برای دسترسی به داشبورد از کامپیوتر خودتان:

```bash
ssh -N -L 8787:127.0.0.1:8787 -L 1088:127.0.0.1:1088 user@IRAN_SERVER
```

## فایروال و بررسی اتصال

با تنظیم پیش‌فرض TCP در رفت و UDP در برگشت، ورودی **TCP 19443** روی خارج از مبدأ `client-source` و ورودی **UDP 19444** روی ایران از مبدأ `server-source` باید در فایروال سیستم و میزبان مجاز باشند. اگر حامل‌ها را عوض می‌کنید، پروتکل قواعد هم باید تغییر کند. پورت‌های داخلی لایه رمز‌شده، پل، SOCKS و داشبورد را عمومی نکنید.

TCP حامل، اتصال عادی TCP نیست و ممکن است فایروال stateful به قاعده صریح نیاز داشته باشد. NAT، فیلتر مبدأ، rp_filter یا محدودیت میزبان می‌توانند بسته‌ها را حذف کنند. نصاب مجوز raw socket و وجود route به همتا را بررسی می‌کند؛ این بررسی محلی، عبور Spoof در شبکه میزبان را ثابت نمی‌کند. فایروال، sysctl و rp_filter را خودکار تغییر نمی‌دهد.

```bash
sudo systemctl status 'tunnelguard-spoof-*'
sudo journalctl -u tunnelguard-spoof-client-carrier -n 50 --no-pager
curl --noproxy '' --proxy socks5h://127.0.0.1:11004 https://example.com
```

هسته upstream الزام UID صفر دارد؛ سرویس حامل با root ولی فقط قابلیت **CAP_NET_RAW** اجرا می‌شود و CAP_NET_ADMIN ندارد. لایه TLS و نگهبان با کاربر محدود اجرا می‌شوند. این نصاب ICMP/ICMPv6 و XDP را فعال نمی‌کند.

گواهی TLS اعتبارسنجی می‌شود و کلید خصوصی سرور منتقل نمی‌شود. گواهی **۳۶۵ روز** اعتبار دارد و تمدید خودکار ندارد؛ پیش از پایان اعتبار، دو سمت را هماهنگ دوباره جفت کنید.

## نصب آفلاین و حذف

اگر GitHub روی سرور باز نمی‌شود، فایل‌های معماری مناسب را از [sing-box](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2) و [Parsa](https://github.com/ParsaKSH/spoof-tunnel/releases/tag/v3.1.0-beta.0) جای دیگری دانلود و منتقل کنید؛ به فرمان نصب اضافه کنید:

```bash
--core-archive /root/sing-box-1.14.2-linux-amd64.tar.gz \
--spoof-binary /root/spoof-linux-amd64
```

برای ARM فایل‌های arm64 را بگیرید. همان هش ثابت در نصب آفلاین هم بررسی می‌شود. بدون `--apply` فقط تنظیمات ساخته می‌شود. هر اجرا پوشه خروجی تازه می‌خواهد و نصب موجود را ارتقای درجا نمی‌دهد.

برای حذف، ابتدا نسخه پشتیبان بگیرید. سرویس‌های `tunnelguard-spoof-server-overlay` و `tunnelguard-spoof-server-carrier` روی خارج و سرویس‌های `tunnelguard-spoof-client-overlay` و `tunnelguard-spoof-client-carrier` روی ایران را با `systemctl disable --now` متوقف کنید. اگر نگهبان مستقل ساخته شده، `tunnelguard-spoof-client-guard` را نیز متوقف کنید.

اگر به نگهبان قبلی متصل شده، ابتدا Spoof را از routes و profiles آن حذف و `tunnelguard-client-guard` را restart کنید. پشتیبان دقیق قبل از نصب در `/opt/tunnelguard-spoof/client/guard-backup.json` است؛ فقط وقتی آن را بازگردانید که تغییرات بعدی لازم نباشند.

سپس فایل‌های دقیق همان سرویس‌ها را از `/etc/systemd/system/` حذف کنید، `sudo systemctl daemon-reload` بزنید و پوشه `/opt/tunnelguard-spoof/server` یا `/opt/tunnelguard-spoof/client` را پس از پشتیبان‌گیری پاک کنید. فایل‌های جفت‌سازی و خروجی خصوصی جداگانه نگهداری یا حذف می‌شوند.

هر جفت حامل برای یک سرور ایران است؛ برنامه‌های متعدد از لایه رمز‌شده مشترک استفاده می‌کنند. چند سرور ایران مستقل به نصب‌های جدا نیاز دارند. نتیجه تست‌ها در [TESTING.md](TESTING.md) است؛ اتصال روی اپراتورهای ایران تضمین نشده است.
