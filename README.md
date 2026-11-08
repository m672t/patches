# PatchGuard — هستهٔ اجرا و اعتبارسنجی وصله (بخش نفر ۱)

ابزاری برای پایپ‌لاین CI/CD که با **اجرای واقعی** برنامهٔ ELF (C/C++) روی نسخهٔ پایه و وصله‌شده، تعیین می‌کند آیا
وصلهٔ امنیتی خطا را برطرف کرده، ناقص مانده، خطای تازه آورده یا عملکرد را خراب کرده است — و هر نتیجه را به Diff وصله پیوند می‌دهد.
فقط کتابخانهٔ استاندارد پایتون (≥ 3.9) لازم است؛ به `gcc`، `git` و (اختیاری) `gcov` نیاز دارد.

```
python3 -m patchguard validate -c examples/demo/config.json            # خروجی: خلاصه + report.json ، کد خروج = حکم
python3 -m patchguard validate -c cfg.json --patched-path DIR           # وصلهٔ ندیده (روز دفاع)
python3 -m patchguard validate -c cfg.json --base-rev v1 --patched-rev fix --repo ./repo
python3 -m patchguard validate -c cfg.json --patch-file my.diff -o -    # JSON روی stdout
python3 -m patchguard check-config -c cfg.json
python3 -m patchguard diff -c cfg.json                                  # نگاشت وصله به فایل/تابع/خط
bash examples/demo/run_all.sh                                           # چهار سناریوی الزامی روی نمونه
python3 -m unittest discover -s tests                                   # ۲۹ تست
```

## ۱. معماری

```
config.json ─► sources ─► diffparse/srcmap ─► builder ─► runner ─► analyzer ─► verdict ─► report
   (هدف)     (dir/git)   (Diff + توابع)      (هر نسخه×مود)  (ماتریس اجرا)  (قضاوت)   (۰/۱۰/۲۰/۳۰/۴۰)  (JSON+متن)
                                                                  │
                                        observation (طبقه‌بندی)  correlate (پیوند خطا↔Diff)  coverage (gcov)
```

| ماژول | وظیفه |
|---|---|
| `config.py` | بارگذاری/اعتبارسنجی؛ افزودن برنامهٔ جدید فقط با config؛ اعمال override های CLI |
| `sources.py` | تهیهٔ سورس **دست‌نخوردهٔ** هر نسخه (پوشه یا `git archive` از commit) + محاسبهٔ Diff |
| `diffparse.py` | پارس unified diff (خطوط حذف/اضافه، نقطهٔ درج) و Diff دو درخت بدون نیاز به git |
| `srcmap.py` | نگاشت «خط ← تابع» برای C/C++ (حذف کامنت/رشته، تطبیق آکولاد) |
| `builder.py` | ساخت هر (نسخه × مود) در کپی جداگانه؛ ثبت لاگ و SHA-256 باینری |
| `runner.py` | اجرای واقعی با محدودیت یکسان (timeout، rlimit، env ثابت)، ثبت exit/signal/stdout/stderr، تکرار برای پایداری |
| `observation.py` | طبقه‌بندی پایه: ASan/UBSan، canary/fortify/glibc-abort، سیگنال؛ استخراج پشتهٔ فراخوانی |
| `correlate.py` | **پیوند خطا به وصله** (سطوح زیر) |
| `analyzer.py` | منطق Fixed / Fix-Incomplete / Issue-New / Func-Regression / Inconclusive |
| `verdict.py` | کد خروج با اولویت ۳۰ > ۱۰ > ۲۰ > ۴۰ > ۰ و «وضعیت‌های مستقل» |
| `report.py`, `cli.py`, `pipeline.py`, `plugins.py` | گزارش، CLI، هماهنگی مراحل، نقاط اتصال |

## ۲. منطق تصمیم (قابل تکرار: شواهد یکسان ⇒ حکم یکسان)

هر تست در هر مود (`release`، `sanitized`) روی هر دو نسخه با محدودیت یکسان `repeats` بار (پیش‌فرض ۳) اجرا می‌شود.
اگر بازپخش‌ها یکسان نباشند، نتیجه **ناپایدار** است و حکم نمی‌دهیم (INCONCLUSIVE).

| پایه | وصله‌شده | وضعیت |
|---|---|---|
| خطای تأییدشده | بدون خطا | `FIXED` (در محدودهٔ آزمون‌ها) |
| خطای تأییدشده | **همان خطا** (نوع یکسان + همان تابع بالای پشته) | `FIX_INCOMPLETE` ← کد ۱۰ |
| خطای تأییدشده | خطای تأییدشدهٔ دیگر | `ISSUE_NEW` ← کد ۱۰ |
| سالم | خطای تأییدشده | `ISSUE_NEW` (علیت ثابت‌شده فرض نمی‌شود؛ در `correlation.note` آمده) |
| هر کدام | توقف طبقه‌بندی‌نشده / timeout / ناپایدار | `INCONCLUSIVE` ← کد ۴۰ |
| مرجع مستقل برقرار | مرجع نقض | `FUNC_REGRESSION` ← کد ۲۰ |
| پایه خودش مرجع را نقض می‌کند | — | `INCONCLUSIVE` (مرجع/تست نامعتبر) |

* «خطای تأییدشده» یعنی گزارش Sanitizer، پیام canary/fortify/glibc، یا سیگنالی که تست در `expect.signal` اعلام کرده؛ `SIGSEGV` خالی به‌تنهایی کافی نیست.
* مودها جدا مقایسه می‌شوند (release با release، sanitized با sanitized) و در یافته با هم ادغام می‌شوند؛ مود sanitized برای جزئیات اولویت دارد.
* خطای تأییدشدهٔ مود ابزارگذاری‌شده، پسرفت عملکردی هم حساب **نمی‌شود** (جداگانه `ISSUE_NEW` است).
* کد ۰ فقط وقتی: خطای هدف روی پایه پایدار بازتولید شود، روی وصله دیده نشود، خطای تأییدشدهٔ دیگری نباشد، حداقل یک تست عملکردی با مرجع مستقل ارزیابی و همه موفق باشند.

### کدهای خروج
| کد | برچسب | معنا |
|---|---|---|
| 0 | PASS | همهٔ شرایط بالا |
| 10 | REMAINS_VULN / ISSUE_NEW | `FIX_INCOMPLETE` یا `ISSUE_NEW` وجود دارد |
| 20 | REGRESSION_FUNC | دست‌کم یک تست عملکردی معتبر که روی پایه موفق بود روی وصله شکست خورد |
| 30 | ERROR_CONFIG_OR_BUILD | config ناقص، شکست ساخت، خطای سورس یا خطای داخلی ابزار |
| 40 | INCONCLUSIVE | بازتولید نشدن خطای پایه، ناپایداری، توقف طبقه‌بندی‌نشده، نبود تست عملکردی |

اولویت هم‌زمانی: **۳۰ ← ۱۰ ← ۲۰ ← ۴۰ ← ۰**. همهٔ وضعیت‌ها مستقل در `verdict.independent_states` و `contributing_codes` می‌مانند.

## ۳. پیوند خطا به وصله (Correlation)

شواهد از **پشتهٔ فراخوانی کامل** (نه فقط فریم صفر) گرفته می‌شود، چون محل خطا لزوماً خط تغییرکرده نیست:

| سطح | معنا | `relation` |
|---|---|---|
| `direct_line` | فریم روی خطی است که وصله تغییر داده، یا گارد دقیقاً قبل از همان دستور درج شده | linked |
| `changed_function` | فریم (در هر عمق پشته) داخل تابعی است که وصله تغییر داده | linked |
| `execution_path` | gcov نشان می‌دهد اجرا از خطوط تغییرکرده گذشته **و** نتیجه بین دو نسخه فرق دارد | linked |
| `near_line` / `changed_file` | مجاورت یا هم‌فایلی صرف | weak (برای ادعا کافی نیست) |
| `unknown` | شواهد ناکافی؛ حدس زده نمی‌شود | unknown |

پایه با سمت «قدیم» Diff و وصله‌شده با سمت «جدید» تطبیق داده می‌شود.

## ۴. فایل پیکربندی (افزودن برنامهٔ جدید = فقط config)

```jsonc
{
  "name": "greet-demo", "workdir": ".patchguard",
  "versions": { "base": {"path": "base"} | {"git": {"repo": ".", "rev": "abc123", "subdir": "opt"}},
                "patched": {...} },
  "diff":  { "file": "optional.patch", "exclude": ["*.o"] },
  "build": { "timeout": 600, "modes": {
      "release":   { "cmd": "...", "binary": "greet", "env": {} },   // الزامی: باینری نهایی
      "sanitized": { "cmd": "... -fsanitize=address,undefined ...", "binary": "greet" },
      "coverage":  { "cmd": "... --coverage -O0 ...", "binary": "greet" } } },   // اختیاری
  "run":   { "timeout": 5, "repeats": 3, "cpu_seconds": 10, "memory_mb": 1024, "jobs": 1,
             "exec_prefix": [], "env": {} },          // exec_prefix: پیشوند ایزوله‌سازی (docker/bwrap/prlimit)
  "plugins": ["plugins/boundary.py"],
  "tests": [ ... ]   // یا "tests_file": "tests.json"
}
```

**تست** (`category`: exploit | functional | boundary | invalid ، `role`: target | variant | check):
```jsonc
{ "id": "poc_original", "category": "exploit", "role": "target",
  "stdin": {"text": "A", "repeat": 40, "suffix": "\n"},        // text | hex | b64 | path ، + repeat/prefix/suffix
  "args": ["--in", "{file:in.bin}"], "files": {"in.bin": {"hex": "00ff"}},   // {cwd} و {file:NAME} جایگزین می‌شوند
  "timeout": 5, "env": {},
  "expect": {"exit_code": 0, "stdout": "...", "stdout_contains": "...", "stdout_regex": "...",
             "exit_code_in": [0,2], "signal": "SIGSEGV"} }     // مرجع مستقل؛ هرگز خروجی وصله نیست
```
* `target`: باگ اصلی (باید روی پایه رخ دهد). `variant`: ورودی دیگری که همان آسیب‌پذیری را می‌زند (برای تشخیص وصلهٔ ناقص). `check`: بقیه.
* حداقل یک تست `target` لازم است (وگرنه کد ۳۰).

## ۵. خروجی JSON (`schema_version 1.0`)

`tool`, `target`, `versions.{base,patched}.{id (commit/هش درخت), kind, origin, binaries.<mode>.{path,sha256}}`, `builds[]`,
`diff.{origin,path,files[{path,hunks,changed_functions}],stats}`, `tests[]` (به‌تفکیک مود: خروجی هر دو نسخه، exit/signal/stdout/stderr،
نوع خطا، مکانیزم تشخیص، فریم‌ها، مسیر artifact ها)، `findings[]` (`id,status,kind,test_id,modes,reason,error,correlation,base,patched`),
`errors[]`, `warnings[]`, `verdict.{label,exit_code,contributing_codes,independent_states,reasons,counts}`.
ورودی دقیق هر تست در `<workdir>/artifacts/inputs/<test_id>/` و stdout/stderr هر اجرا در `<workdir>/artifacts/runs/...` ذخیره می‌شود.

## ۶. قرارداد اتصال برای نفرات ۲ تا ۴ (بدون ویرایش هسته)

پلاگین = فایل پایتون در `config.plugins`؛ هر کدام از این توابع اختیاری است:

```python
def provide_tests(ctx) -> list[dict]        # نفر ۲: ورودی‌های مرزی/تصادفی با همان قالب تست بالا
def classify_run(obs, ctx) -> dict | None   # نفر ۲: دسته‌بندی دقیق‌تر؛ فیلدهای error_type/mechanism/confirmed را بازنویسی می‌کند
def post_analysis(ctx, report) -> None      # نفر ۲/۳/۴: افزودن finding (مثلاً NEW_ISSUE/hardening) یا بخش جدید به report
```
`ctx` شامل: `cfg`, `workdir`, `versions` (سورس‌ها + commit), `builds[(version,mode)]` (مسیر باینری/هش/محیط ساخت),
`tests`, `inputs[test_id]` (بایت‌های دقیق ورودی)، `cells[(version,mode,test_id)]` (همهٔ بازپخش‌ها)، `diff_index`, `diff_text`.
وضعیت‌های finding که حکم را تغییر می‌دهند: `FIX_INCOMPLETE, ISSUE_NEW, FUNC_REGRESSION, INCONCLUSIVE, FIXED`؛
`WARNING`/`INFO` هرگز کد خروج را عوض نمی‌کنند (مناسب هشدار hardening).

* **نفر ۲:** `provide_tests` + `classify_run`؛ تفکیک release/sanitized همین حالا در هسته هست (`build.modes`) و فقط دستور ساخت sanitizer را تنظیم کنید.
* **نفر ۳:** در `post_analysis` از `ctx.builds`, `ctx.inputs`, `ctx.cells` و `ctx.versions[*].version_id` برای bundle/minimization/regression-test و بررسی ELF استفاده کنید.
* **نفر ۴:** config هدف‌ها، فایل CI (`patchguard validate ...; exit $?`) و `run.exec_prefix` برای کانتینر.

نمونهٔ CI (کد خروج مستقیماً تصمیم پایپ‌لاین است):
```yaml
- run: python3 -m patchguard validate -c targets/libfoo/config.json -o report.json
- uses: actions/upload-artifact@v4
  if: always()
  with: { name: patchguard, path: "report.json\ntargets/libfoo/.patchguard/artifacts" }
```

## ۷. محدودیت‌های شناخته‌شده (در دفاع صادقانه بگویید)
* `srcmap` مبتنی بر قاعده است (نه parser کامل)؛ ماکروهای پیچیده یا قالب‌های سنگین ممکن است تابع را اشتباه تشخیص دهند → در این حالت سطح به `changed_file` یا `unknown` می‌افتد، نه ادعای غلط.
* در مود release فریم‌های سورس‌دار وجود ندارد؛ پیوند به Diff عمدتاً از مود sanitized و gcov می‌آید.
* gcov برای اجراهایی که crash می‌کنند خروجی ندارد؛ برای نسخهٔ پایه‌ای که crash می‌کند از پشتهٔ Sanitizer استفاده می‌شود.
* مقایسهٔ `FIX_INCOMPLETE` بر پایهٔ «نوع خطا + تابع بالای پشته» است؛ دو باگ متفاوت با نوع و تابع یکسان یکی حساب می‌شوند.
* ایزوله‌سازی واقعی (کانتینر) وظیفهٔ نفر ۴ است؛ هسته فقط rlimit و `exec_prefix` را فراهم می‌کند.

## ۸. نکات دفاع فردی (نفر ۱)
۱) چرا کد خروج اولویت ۳۰/۱۰/۲۰/۴۰/۰ دارد و چرا وضعیت‌ها مستقل ذخیره می‌شوند → `verdict.py`.
۲) چرا `FIX_INCOMPLETE` از طریق تست‌های `variant` پیدا می‌شود نه با خود PoC → `analyzer.eval_security`.
۳) چرا هر جا شواهد کم است `INCONCLUSIVE`/`unknown` می‌دهیم → جدول بخش ۲ و ۳.
۴) تغییر محدود احتمالی: افزودن مود/سطح correlation، تغییر معیار `same_bug`، افزودن کلید `expect`، افزودن خروجی در `report.py` — هرکدام با اجرای `examples/demo/run_all.sh` راستی‌آزمایی می‌شود.
