# انتخاب و نصب مسیرهای بیشتر

[English](TRANSPORTS.md)

ده گزینهٔ نصب: Shadowsocks 2022، Trojan/TLS، Hysteria2/QUIC، SSH معکوس، VMess/WebSocket/TLS، VLESS/TLS، TUIC/QUIC، AnyTLS، WireGuard و Spoof با پوشش Hysteria2. همهٔ آن‌ها روی هر شبکه کار نمی‌کنند؛ مسدود بودن یک IP ممکن است چند پروتکل را هم‌زمان از کار بیندازد. تعداد گزینه‌ها نرخ موفقیت تضمین‌شده نیست.

داشبورد «قابل نصب» را از «پیکربندی‌شده» و «سالم» جدا می‌کند. Spoof تا پیش از [جفت‌سازی](SPOOF.fa.md) در انتخاب مسیر زنده ظاهر نمی‌شود. [SSH معکوس](REVERSE.fa.md) و [WireGuard](WIREGUARD.fa.md) نصب‌کنندهٔ جدا در همین پروژه دارند؛ نصب جداگانهٔ کد از پروژهٔ دیگری لازم نیست. هسته‌های دانلودشده همچنان از منابع رسمی با هش ثابت بررسی می‌شوند.

## نصب تازهٔ هفت پروتکل sing-box

روی خارج:

```bash
sudo python3 deploy.py server --address YOUR_EXIT_IP \
  --extra-ports 18446 18447 18448 18449 \
  --output /root/tg-server --apply
```

فایل خصوصی `pairing.json` را به ایران ببرید و کلاینت را طبق [راهنما](DEPLOY.fa.md) نصب کنید. پورت‌های خروجی پایه: TCP/18443، TCP/18444، UDP/18445؛ اضافه‌ها به ترتیب TCP/18446، TCP/18447، UDP/18448 و TCP/18449. SOCKSهای ایران به ترتیب پایه 11001–11003 و اضافه‌ها 11006–11009 هستند؛ 11004 برای Spoof و 11005 برای SSH معکوس رزرو شده‌اند.

## اضافه کردن به نصب موجود

این دستورات تنظیمات پایه و رمزهای فعلی را حفظ می‌کنند. ابتدا نسخهٔ جدید کد را بگیرید. روی خارج:

```bash
sudo python3 deploy_extra.py server --address YOUR_EXIT_IP \
  --output /root/tg-extra-server --apply
```

فایل خصوصی `/root/tg-extra-server/pairing.json` را امن به ایران منتقل کنید؛ سپس:

```bash
sudo python3 deploy_extra.py client --bundle /root/extra-pairing.json \
  --output /root/tg-extra-client --apply
```

نصب‌کنندهٔ اضافه‌ها در نصب موجود به هستهٔ sing-box پایه تکیه می‌کند. از سرور و کلاینت snapshot می‌گیرد و خطای فعال‌سازی را بازمی‌گرداند. افزودن مسیر نگهبان را restart می‌کند و اتصال‌های موجود ممکن است قطع شوند. برای تغییر پورت‌ها `--ports` با چهار مقدار و برای پورت‌های محلی `--local-base` را استفاده کنید. فایروال تغییر نمی‌کند.

گردش هماهنگ گواهی و رمزِ نصب پایه در نسخهٔ جدید، هر هفت پروتکل را پشتیبانی می‌کند. هر دو سمت باید نسخهٔ جدید ابزار نگهداری را داشته باشند. رمز و UUID مربوط به هر transport با هم عوض می‌شوند. گواهی همچنان 365 روز اعتبار دارد. WebSocket در این تنظیم مستقیم به IP وصل می‌شود؛ CDN یا گواهی عمومی دامنه خودکار ایجاد نمی‌کند.

## هسته‌های خارجی

Backhaul، Rathole، FRP، GOST و SSH عادی adapter دارند؛ آن‌ها را «نصب خودکار جفت‌شده» حساب نکنید. پس از پیکربندی واقعی هسته و فراهم کردن SOCKS یا HTTP CONNECT می‌توان خروجی را اضافه کرد:

```bash
sudo python3 manage.py route-add --name MyBackhaul \
  --proxy socks5h://127.0.0.1:12001 --layer Backhaul --apply
```

این دستور هستهٔ خارجی را نصب نمی‌کند. برای [فوروارد x-ui](FORWARDING.fa.md)، پورت inbound کاربران را مشخص کنید.
