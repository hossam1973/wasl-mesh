# وَصْل (Wasl)

مراسلة ومكالمات صوت وفيديو ونقل ملفات من هاتف إلى هاتف، بلا إنترنت ولا شريحة ولا رقم هاتف ولا خادم.

- **التطبيق**: مجلد [`app/`](app/) — تطبيق ويب قابل للتثبيت (PWA). التفاصيل في [`app/README.md`](app/README.md).
- **طبقات الاتصال**: Wi-Fi / نقطة اتصال، WebRTC، مايكروويف (أي رابط IP)، LoRa (USB/KISS)، HF/VHF (كرت الصوت أو TNC). Bluetooth LE وWi-Fi Direct بلا نقطة اتصال في النسخة الأصلية القادمة.
- **الأمان**: هوية من زوج مفاتيح على الجهاز، تشفير من طرف إلى طرف (ECDH P-256 + AES-GCM)، توقيع ECDSA، سجل متسلسل موقّع بشهود.
- **مركز القيادة**: صحة الشبكة، الأجهزة، إذاعات مع تأكيد الاستلام، قرارات بتوقيع متعدد، مؤقّت الأمان.

## تطبيقات Android و iOS
نفس التطبيق مغلّف بـ Capacitor مع إضافة أصلية [`plugins/wasl-nearby`](plugins/wasl-nearby):
- **Android**: Google Nearby Connections (Bluetooth LE + Bluetooth + Wi-Fi Direct تلقائياً، بلا نقطة اتصال).
- **iOS**: Apple Multipeer Connectivity (Bluetooth + Wi-Fi نظير لنظير).
- الهواتف القريبة تتصل تلقائياً دون مسح رمز، وتنقل نفس الحزم الموقّعة والمشفّرة.
- بين Android و iPhone: عبر نقطة اتصال مشتركة ورمز QR (WebRTC)، أو LoRa.

البناء تلقائي على GitHub Actions عند كل دفع إلى `main`: ملف APK جاهز للتثبيت، وبناء iOS للمحاكي للتحقق. التثبيت على iPhone حقيقي يحتاج حساب Apple Developer للتوقيع.

بناء محلي:
```bash
npm ci && npx cap sync
npx cap open android   # Android Studio
npx cap open ios       # Xcode (macOS)
```

## النشر
يُنشر مجلد `app/` على GitHub Pages. افتح الرابط مرة واحدة على كل هاتف وثبّته، ثم يعمل بلا إنترنت.

ملفات أخرى: `index.html` (عرض تفاعلي لمحاكاة الشبكة)، `nexlink-review.html` (مراجعة منصة NexLink).
