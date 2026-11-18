# وَصْل (Wasl)

مراسلة ومكالمات صوت وفيديو ونقل ملفات من هاتف إلى هاتف، بلا إنترنت ولا شريحة ولا رقم هاتف ولا خادم.

- **التطبيق**: مجلد [`app/`](app/) — تطبيق ويب قابل للتثبيت (PWA). التفاصيل في [`app/README.md`](app/README.md).
- **طبقات الاتصال**:
  - Bluetooth LE و Wi-Fi Direct (تطبيق Android) / Bluetooth و Wi-Fi نظير لنظير (تطبيق iOS): اكتشاف واتصال تلقائي.
  - Wi-Fi / نقطة اتصال + WebRTC: فيديو وصوت وملفات.
  - مايكروويف وشبكات IP (AREDN، جسور 5 GHz): اكتشاف تلقائي على الشبكة، أو الاتصال بموقع بعيد بعنوانه.
  - LoRa: عبر USB مع RNode أو أي KISS TNC.
  - HF / VHF: مودم صوتي مدمج، أو TNC عبر USB، أو VARA HF / ARDOP / Direwolf عبر TCP بحزم AX.25 تحمل نداء الهواة.
  - الصوت عبر الهواء: بيانات بين هاتفين عبر السماعة والميكروفون بلا أي شبكة.
  - ناقل يدوي: ملف رسائل يُنقل بفلاشة أو بطاقة ذاكرة، مع إيصالات تعود بالطريقة نفسها.
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
