# WireGuard با هستهٔ sing-box

[English](WIREGUARD.md)

نصب‌کننده از endpoint کاربران WireGuard در sing-box 1.14.2 استفاده می‌کند. interface کرنل، route پیش‌فرض، ip_forward و NAT میزبان را تغییر نمی‌دهد. خروجی محلی برای نگهبان SOCKS است؛ درگاه و فوروارد برنامه همچنان TCP هستند. این یک VPN سراسری برای همهٔ برنامه‌ها یا پیاده‌سازی UDP فوروارد عمومی نیست.

روی خارج:

```bash
sudo python3 deploy_wireguard.py server --address YOUR_EXIT_IP \
  --output /root/tg-wg-server --apply
```

UDP/18450 را در فایروال ارائه‌دهنده/میزبان اجازه دهید. `--port` قابل تغییر است. فایل `pairing.json` حاوی کلید خصوصی کلاینت است؛ آن را فقط از SSH مورد اعتماد منتقل کنید. کلید خصوصی سرور داخل pairing نیست.

روی ایران، پس از نصب پایه:

```bash
sudo python3 deploy_wireguard.py client --bundle /root/wg-pairing.json \
  --output /root/tg-wg-client --apply
```

مسیر `wireguard` روی SOCKS محلی 11010 به پروفایل‌های All و WireGuard اضافه می‌شود. تغییر آن با `server --socks-port` هنگام تولید pairing است. آدرس‌های داخلی 10.77.0.1/30 و 10.77.0.2/30 فقط در stack کاربران هستند. یک پل SOCKS روی loopback خارج (پورت 11011، قابل تغییر با --bridge-port) داخل WireGuard قرار دارد؛ نام مقصد در خارج resolve می‌شود. بسته‌های WireGuard به آدرس داخلی می‌روند، بنابراین مقصدهای loopback برنامه نیز درست پشتیبانی می‌شوند.

نصب آفلاین با `--core-archive` همان آرشیو رسمی و هش ثابت را می‌پذیرد. پیش‌نیاز تولید کلید: openssl. برنامه فایروال را تغییر نمی‌دهد و مسدود شدن UDP می‌تواند این مسیر را از کار بیندازد.

```bash
sudo systemctl status tunnelguard-wireguard-client-core
sudo python3 maintenance.py upgrade --target wireguard-client --cores
sudo python3 maintenance.py uninstall --target wireguard-client
```

سمت خارج target برابر `wireguard-server` است. کلاینت را پیش از حذف نگهبان پایه حذف کنید. snapshotها کلید خصوصی دارند؛ نگهداری آن‌ها باید خصوصی باشد. WireGuard گواهی TLS با انقضا ندارد؛ گردش کلید هماهنگ خودکارِ ابزار base برای این target پشتیبانی نمی‌شود.

مرجع: [WireGuard endpoint در sing-box](https://sing-box.sagernet.org/configuration/endpoint/wireguard/).

## شروع اتصال از خارج

اگر جهت مستقیم کار نمی‌کند، می‌توانید هنگام تولید سمت خارج از `--direction reverse --client-address YOUR_IRAN_IP` استفاده کنید. در این حالت خارج handshake را به UDP/18451 ایران آغاز می‌کند؛ این پورت باید در ایران باز باشد. `--client-port` قابل تغییر است. این حالت همچنان WireGuard است و یک مسیر مستقل اضافه برای شمارش مصنوعی مسیرهای سالم محسوب نمی‌شود.

برای تغییر نصب موجود، در فرمان server گزینه‌های بالا و `--replace` را با output جدید بدهید؛ pairing جدید را منتقل کنید و فرمان client را نیز با output جدید و `--replace --apply` اجرا کنید. هر سمت snapshot می‌گیرد. کلیدها عوض می‌شوند و تا تکمیل هر دو سمت مسیر قطع است. پورت SOCKS موجود را هنگام جایگزینی تغییر ندهید. این روش تضمین عبور UDP نیست.
