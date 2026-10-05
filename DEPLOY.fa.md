# نصب خودکار دو سمت — نسخه ۲.۱

[English](DEPLOY.md) · [راهنمای اصلی](README.fa.md)

نصاب جدید هسته **sing-box 1.14.2** را دانلود و با SHA256 مشخص بررسی می‌کند؛ سه مسیر **Shadowsocks 2022، Trojan/TLS و Hysteria2/QUIC** را در دو سمت می‌سازد، رمزهای تصادفی و گواهی TLS تولید می‌کند و سرویس‌ها و تنظیمات TunnelGuard را راه می‌اندازد.

محیط هدف **Ubuntu 24.04 با معماری amd64 یا arm64 و systemd** است. Python 3.11+ لازم است. نصب واقعی با `--apply` و دسترسی root انجام می‌شود. نصب Spoof و سایر هسته‌ها هنوز در این نصاب نیست.

سرور خروجی معمولاً خارج ایران است و سمت کلاینت روی سرور ایران قرار می‌گیرد؛ کلاینت به خارج وصل می‌شود. این نصب «تانل معکوس» نیست. سه پروتکل روی یک IP، تنوع لایه ایجاد می‌کند؛ اگر خود IP از دسترس خارج شود هر سه مسیر ممکن است قطع شوند. برای استقلال سرورها باید مسیرهای سرورهای دیگری را نیز به TunnelGuard اضافه کنید.

## ۱. آماده‌سازی هر دو سرور

روی هر دو اجرا کنید:

```bash
sudo apt update
sudo apt install -y git python3 curl openssl ca-certificates
git clone https://github.com/Mehdi682007/TunnelGuard.git
cd TunnelGuard
```

## ۲. نصب روی سرور خارج

به‌جای آدرس نمونه، IP عمومی واقعی سرور خارج را وارد کنید:

```bash
sudo python3 deploy.py server --address 203.0.113.10 \
  --output /root/deployment-server --apply
```

نصب در `/opt/tunnelguard-node/server` انجام می‌شود و سرویس `tunnelguard-server-server` فعال می‌شود. پورت‌های **18443/TCP، 18444/TCP و 18445/UDP** باید در فایروال سرور و پنل میزبان باز باشند. اگر UFW از قبل تنظیم شده است:

```bash
sudo ufw allow 18443/tcp
sudo ufw allow 18444/tcp
sudo ufw allow 18445/udp
```

نصاب فایروال را فعال یا بازنشانی نمی‌کند. بدون حفظ دسترسی SSH، UFW را فعال نکنید. برای پورت دلخواه گزینه `--ports 19443 19444 19445` را اضافه کنید؛ سه پورت متفاوت و بالاتر از ۱۰۲۳ لازم است.

## ۳. انتقال فایل اتصال و نصب روی سرور ایران

روی سرور خارج فایل `/root/deployment-server/pairing.json` ساخته می‌شود. این فایل **رمز اتصال دارد**؛ آن را در ویدئو، گیت‌هاب یا پیام عمومی نمایش ندهید. کلید خصوصی TLS در این فایل نیست.

فایل را از طریق SSH/SCP منتقل کنید. نمونه زیر روی سرور ایران اجرا می‌شود و فرض می‌کند ورود SSH کاربر root به سرور خارج از قبل مجاز است:

```bash
sudo scp root@203.0.113.10:/root/deployment-server/pairing.json /root/pairing.json
sudo chmod 600 /root/pairing.json
sudo python3 deploy.py client --bundle /root/pairing.json \
  --output /root/deployment-client --apply
```

اثر انگشت SSH سرور را از مسیر مطمئن بررسی کنید و بررسی host key را خاموش نکنید. اگر با کاربر دیگری وصل می‌شوید، از روش امن انتقال فایل همان حساب استفاده کنید؛ برای این ابزار ورود root را فعال نکنید.

نصاب سه خروجی محلی روی `127.0.0.1:11001` تا `11003` و نگهبان را روی پورت `1088` می‌سازد. داشبورد روی `8787` است. هر سه مسیر خودکار وارد پروفایل‌های All، TCP و QUIC می‌شوند. برای جابه‌جایی پورت‌های هسته گزینه `--local-base 12001` را اضافه کنید. اگر TunnelGuard قدیمی این پورت‌ها را اشغال کرده، ابتدا آن را متوقف کنید.

برای دسترسی از کامپیوتر خودتان:

```bash
ssh -N -L 8787:127.0.0.1:8787 -L 1088:127.0.0.1:1088 user@IRAN_SERVER
```

سپس `http://127.0.0.1:8787` را باز کنید. برنامه مصرف‌کننده باید SOCKS5 آدرس `127.0.0.1:1088` با DNS سمت پروکسی استفاده کند. آزمایش روی سرور ایران:

```bash
curl --noproxy "" --proxy socks5h://127.0.0.1:1088 https://example.com
sudo systemctl status 'tunnelguard-client-*'
sudo journalctl -u tunnelguard-client-hysteria2 -n 50 --no-pager
```

## دانلود آفلاین و بررسی فایل

هسته مستقیم از [انتشار رسمی sing-box 1.14.2](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2) دریافت می‌شود و هش آن با مقدار ثابت داخل نصاب مقایسه می‌شود. اگر GitHub روی سرور قابل دسترس نیست، فایل معماری مناسب را جای دیگری دانلود و امن منتقل کنید؛ به فرمان نصب اضافه کنید:

```bash
--core-archive /root/sing-box-1.14.2-linux-amd64.tar.gz
```

برای ARM فایل arm64 لازم است. بررسی هش در نصب آفلاین هم اجباری است. بسته‌های سیستم‌عامل باید قبلاً نصب باشند. باینری در ZIP پروژه قرار نمی‌گیرد؛ هنگام نصب دانلود می‌شود و مجوز آن متعلق به [پروژه sing-box](https://github.com/SagerNet/sing-box) است.

## نگهداری، پیش‌نمایش و حذف

بدون `--apply` فقط فایل‌های خصوصی ساخته می‌شوند و دانلود یا تغییر سرویس انجام نمی‌شود. هر اجرا پوشه خروجی جدید می‌خواهد. ساخت مجدد سمت سرور رمزهای تازه می‌سازد؛ فایل اتصال باید متعلق به همان نصب فعال باشد. بازنویسی نصب موجود، ارتقای درجا و تعویض خودکار رمز پیاده نشده‌اند.

سرویس‌ها با کاربر محدود DynamicUser و تنظیمات خصوصی systemd اجرا می‌شوند. بررسی گواهی TLS فعال است؛ کلاینت به گواهی تولیدشده اعتماد می‌کند. گواهی **۳۶۵ روز** اعتبار دارد؛ قبل از پایان اعتبار برای نصب و جفت‌سازی دوباره هر دو سمت برنامه‌ریزی کنید. تغییر فقط یک سمت اتصال را خراب می‌کند.

اگر ایجاد یا شروع سرویس شکست بخورد، سرویس‌ها و پوشه نصب تازه حذف می‌شوند و خروجی خصوصی برای بررسی باقی می‌ماند. بالا آمدن سرویس به‌تنهایی اثبات اتصال اینترنت نیست؛ سلامت مسیرها را در داشبورد بررسی کنید.

برای حذف، ابتدا از فایل‌های خصوصی پشتیبان بگیرید. روی سرور ایران:

```bash
sudo systemctl disable --now tunnelguard-client-shadowsocks tunnelguard-client-trojan tunnelguard-client-hysteria2 tunnelguard-client-guard
sudo rm /etc/systemd/system/tunnelguard-client-{shadowsocks,trojan,hysteria2,guard}.service
sudo rm -r /opt/tunnelguard-node/client
sudo systemctl daemon-reload
sudo systemctl reset-failed
```

روی سرور خارج:

```bash
sudo systemctl disable --now tunnelguard-server-server
sudo rm /etc/systemd/system/tunnelguard-server-server.service
sudo rm -r /opt/tunnelguard-node/server
sudo systemctl daemon-reload
sudo systemctl reset-failed
```

پوشه‌های خروجی، فایل pairing و قواعد فایروال خودکار حذف نمی‌شوند. وقتی دیگر لازم نیستند جداگانه پاکشان کنید. نصب مجدد اتصال‌های جاری را قطع می‌کند.

Hysteria2 از UDP برای انتقال استفاده می‌کند ولی درگاه TunnelGuard همچنان برای برنامه‌های TCP است. اتصال روی اپراتورهای ایران تضمین نمی‌شود. جزئیات آزمایش‌ها در [TESTING.md](TESTING.md) و منابع قالب‌های پروتکل در [راهنمای انگلیسی](DEPLOY.md) آمده است.
