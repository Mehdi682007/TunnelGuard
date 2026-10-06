# نصب SSH معکوس

[English](REVERSE.md)

خارج اتصال را به SSH ایران آغاز می‌کند و SOCKS را روی loopback ایران فراهم می‌کند. ممکن است وقتی جهت ایران به خارج بسته است کار کند؛ موفقیت در همهٔ شبکه‌ها تضمین نمی‌شود. فقط TCP کاربردی منتقل می‌شود. حساب اختصاصی اجازهٔ shell، فوروارد محلی، Unix socket، PTY، agent، X11 یا TUN ندارد. heartbeat دو سمت، پورتِ نشست مرده را آزاد می‌کند و systemd اتصال را دوباره برقرار می‌کند.

روی خارج، IPها را جایگزین کنید:

```bash
sudo python3 deploy_reverse.py prepare --receiver YOUR_IRAN_IP \
  --sender YOUR_EXIT_IP --output /root/tg-reverse-offer
```

فقط `offer.json` را از کانال SSH مورد اعتماد به ایران ببرید؛ فایل `key` روی خارج می‌ماند. روی ایران، پس از نصب پایه:

```bash
sudo python3 deploy_reverse.py accept --bundle /root/offer.json \
  --output /root/tg-reverse-accept --attach --apply
```

این فرمان حساب `tunnelguard-relay` و تنظیم SSH مختص آن را ایجاد می‌کند. تنظیم sshd پیش از reload اعتبارسنجی می‌شود؛ تنظیمات root عوض نمی‌شوند. fingerprint کلید میزبان ایران را از کانال مطمئن تطبیق دهید. `acceptance.json` را به خارج برگردانید:

```bash
sudo python3 deploy_reverse.py connect --bundle /root/acceptance.json \
  --key /root/tg-reverse-offer/key --output /root/tg-reverse-start --apply
```

روی ایران:

```bash
curl --noproxy '' --proxy socks5h://127.0.0.1:11005 https://www.gstatic.com/generate_204 -I
```

پورت SSH پیش‌فرض 22، SOCKS پیش‌فرض 11005 است؛ `prepare --ssh-port` و `--socks-port` قابل تنظیم‌اند. در این نسخه آدرس‌های جفت IPv4 هستند. نصب بدون `--apply` فقط بررسی می‌شود؛ `prepare` فایل خصوصی می‌سازد. مسیر بعد از `--attach` در نگهبان دیده می‌شود، ولی تنها تست سلامت تعیین می‌کند قابل استفاده است یا نه.

## به‌روزرسانی نصب آزمایشی قبلی

برای مهاجرت همان کلید و حساب، در `prepare` گزینهٔ `--key /root/tunnelguard-field/reverse_ed25519` و در accept/connect گزینهٔ `--adopt-existing` را اضافه کنید. همیشه output جدید انتخاب کنید. کلید موجود باید با پیشنهاد جفت‌سازی مطابقت داشته باشد؛ فایل‌های تغییرکرده خصوصی پشتیبان‌گیری می‌شوند. پس از تغییر heartbeat، نشست موجود باید دوباره متصل شود.

سرویس خارج `tunnelguard-reverse-ssh` است. مسیر نصب آن `/opt/tunnelguard-reverse`، تنظیم ایران `/etc/ssh/sshd_config.d/90-tunnelguard-relay.conf` است. به‌روزرسانی/حذف این حساب و سرویس هنوز زیر فرمان‌های عمومی maintenance نیست؛ با همین نصب‌کننده و مهاجرت صریح نگهداری می‌شود. برای توقف، سرویس خارج را `disable --now` کنید و مسیر `reverse-ssh` و مقصدهای وابسته را از نگهبان بردارید. حذف حساب فقط پس از قطع نشست آن و اطمینان از نبود استفادهٔ دیگر انجام شود؛ فایل‌ها خودکار پاک نمی‌شوند.

مرجع: [OpenSSH remote dynamic forwarding](https://man.openbsd.org/ssh#R).
