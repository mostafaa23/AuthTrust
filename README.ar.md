<div dir="rtl" markdown="1">

# Wily — شرح المشروع بالكامل بالعربي

> **ماسح أمان سحابي (Cloud-native) يعمل بأسلوب Black-box على الـ APIs والبنية السحابية.**

> **ملاحظة على الأسماء:** الريبو على GitHub اسمه `AuthTrust`، لكن اسم الأداة (الأمر اللي بيتنصّب) واسم الباكدج في بايثون الاتنين `wily`. فلما تشوف `wily` في الأوامر، ده هو نفسه مشروع AuthTrust.

هذا المستند شرح كامل للمشروع موجّه لأي حد بيقرأ الريبو — زميل، مُقيّم، أو دكتور بيقيّم مشروع تخرّج. بيغطي **الفكرة والرؤية**، **المعمارية وطريقة الشغل (الـ pipeline)**، **كل ثغرة بيكشفها الماسح (الـ 9 scanners)**، ثم **التثبيت والاستخدام** و**ملاحظة الأمان والأخلاقيات**.

---

## الفكرة والرؤية

**Wily** أداة أمان آلية (automated) للأمن السحابي و الـ bug-bounty. فكرتها الأساسية إنك تبدأ من **دومين واحد** عندك صلاحية تختبره (مثلاً `example.com`)، والأداة تتولّى الباقي:

1. **تكتشف الأصول (assets)** الموجودة تحت الدومين: روابط (URLs)، نقاط API، ملفات JavaScript، buckets على S3، وخدمات سحابية.
2. **تعمل جولة كشف واسعة ورخيصة (broad detection pass)** على كل أصل اكتشفته — فحوصات بسيطة وسريعة تغطي أكبر مساحة ممكنة.
3. **تشغّل الفحوصات العميقة والأغلى فقط لمّا يكون فيه نتيجة سابقة تبرّرها** — ده المبدأ المحوري في المشروع: **finding-driven** (مدفوع بالنتائج). يعني الفحص العدواني/المكلف ما بيتشغّلش على كل حاجة، بيتشغّل بس لما مؤشّر من جولة الكشف يشاور عليه (مثلاً: لقينا كسر في التفويض على endpoint ⟵ نعمّق باختبار JWT أو BOLA على نفس الـ endpoint).
4. **تربط النتائج ببعضها (correlate)**، تشيل المكرر (dedup)، وتحسب **درجة خطورة (risk score)** لكل نتيجة.
5. **تطلّع تقرير موحّد** بصيغ **JSON / HTML / SARIF**، مع أدلّة (evidence) وتقييم severity و confidence لكل finding — وممكن يتبعت بالإيميل.

الأداة مصمّمة إنها **عامة وواسعة (broad/generic)**: تشتغل على أي دومين مش مربوطة بتطبيق معيّن. ومن ناحية التشغيل، فيها قصّة نشر (deploy) عالية المستوى: ممكن تشتغل في **Docker على EC2**، مع **Lambda لإرسال التقارير بالإيميل** (كبنية اختيارية للنشر).

الفلسفة اللي بتميّزها إنها مش بس "بتكتشف الموجود"، لكنها **بتقرّر بذكاء إيه الفحص اللي يستاهل يتشغّل دلوقتي** على أساس الدليل — وده بيوفّر وقت وطلبات (requests) ويقلّل الضجيج.

---

## إزاي بيشتغل — المعمارية والـ Pipeline

المنسّق الرئيسي (orchestrator) موجود في `src/wily/cli/commands/scan_all.py` وبيشغّل الأمر `wily scan <domain>`. الـ pipeline بيمرّ بالمراحل دي بالترتيب:

### 1) الدومين ← الاكتشاف (Discovery)
لمّا تدّي دومين، بتشتغل مرحلة اكتشاف الأصول (`recon/api_discovery.py`): اكتشاف نقاط الـ API من مواصفات **OpenAPI**، ومن تحليل ملفات **JavaScript**، ومن **wordlist** (قوائم مشتقّة من SecLists). في الوضع الافتراضي للـ `scan` بيشتغل بشكل **عدواني وعميق** (`aggressive=True`, `deep_fuzz=True`) عشان حتى الأهداف المحمية اللي بترجّع endpoints قليلة تاخد مسح شامل.

### 2) استيراد ترافيك اختياري (Burp / HAR)
تقدر بدل الاكتشاف الحيّ (أو بجانبه) تستورد ترافيك جاهز **offline** من تصدير **Burp Suite** (`--burp-xml`) أو من **HAR** من الـ DevTools (`--import-har`). التحليل بيحصل بدون إعادة إرسال (no replay): بيطلّع منه endpoints و bearer tokens و روابط S3. ولو ما اديتش دومين لكن الاستيراد فيه endpoints، الأداة بتاخد أول host منها كنطاق للمسح (المنطق في `recon/traffic_import.py`).

### 3) فلترة النطاق (Scope filtering) — الـ ScopeManager وأنواعه الثلاثة
كل حاجة بتعدّي على `core/scope_manager.py`، اللي بيضمن إن الأداة **ما تلمسش حاجة برّه الصلاحية**. وفيه **٣ أنواع من النطاق (scope)**:

- **نطاق الدومينات/الـ CIDRs:** الـ `ScopeManager` بيتبني على الدومين الجذر، وبيسمح بالـ subdomains افتراضيًا (`is_in_scope`)، وبيرفض أي host برّه، والعناوين المحلية محتاجة `--allow-local`. الاستثناءات (excluded hosts) ليها الأولوية على الإدراج.
- **نطاق الـ S3 buckets:** قائمة أسماء buckets أو أنماط glob (مثل `target-*`) عبر `--scope-bucket` أو ملف `--scope-config`. فلو حددت نطاق buckets، الأداة بتفحص بس اللي جوّا النطاق وتتجاهل أي bucket تاني لقيته (`is_bucket_in_scope`).
- **نطاق حسابات AWS / ARNs:** قائمة أرقام حسابات (12 رقم) أو بادئات ARN عبر `--scope-account`، بتقيّد تحليل الـ IAM عشان ما يفكّرش في principals بتخصّ حساب طرف تالت ظهر بالصدفة في ملف التصدير (`is_account_in_scope`).

### 4) التوجيه (Routing)
كل أصل اتكتشف بيتوجّه للفحوصات المناسبة ليه (`classify/router.py` وظيفته `route_asset`): endpoint عادي يروح لفحوصات الـ API، رابط `.js` يروح لفاحص الأسرار، مرجع S3 يروح لفاحص الـ buckets، وهكذا.

### 5) جولة الكشف الواسعة (Broad detection)
على كل endpoint جوّا النطاق، بتشتغل تلقائيًا الفحوصات الرخيصة: **Auth Bypass** (authorizer ناقص / تناقض في الـ methods) و**CORS**، ومعاهم **اكتشاف البراميترات** (`recon/parameter_discovery.py`) عشان نلاقي البراميترات اللي ممكن تكون عرضة لـ **SSRF**. ولو اديت `--token` بيشتغل **JWT**، ولو اديت أكتر من `--identity` بيشتغل **BOLA**.

قبل أي فاحص غالي، فيه **فلترة للأصول الحيّة** (`recon/live_filter.py`, بأسلوب HTTPX): بتدمج الـ endpoints المتطابقة والمتشابهة جدًا (نفس المسار باختلاف الـ object id فقط) — وده بيحصل دايمًا مجانًا (dedup)؛ وفيه اختياري `--probe-live` بيرمي الـ endpoints اللي ما بتردّش على probe بسيط (HEAD/GET) عبر نفس الـ HTTP engine المقيّد بالنطاق.

### 6) الفحوصات العميقة المدفوعة بالنتائج (Finding-driven triggers)
ده قلب الفكرة، ومنطقه في `risk/triggers.py` (الدالة `derive_followups`، وهي دالة **نقيّة/pure** بدون I/O عشان تبقى قابلة للاختبار). بتاخد النتائج اللي طلعت من جولة الكشف + سياق التشغيل (`TriggerContext`)، وتقرّر الفحوصات الأعمق المبرّرة:

- **كسر تفويض** على endpoint ⟵ لو فيه identities نفحصه كهدف **BOLA**؛ ولو فيه token نعمّق عليه **JWT tampering**.
- **SSRF سحابي مؤكّد** ⟵ نصعّد لتأكيد **blind/OOB** لو فيه canary شغّال.
- **bucket عام على S3** (listing/object/ACL) ⟵ (اختياري عبر `--confirm-s3-writes`) نفحص صلاحيات الكتابة/الحذف المستنتجة من الـ ACL (قراءة فقط).
- **تسريب credentials سحابية** (في دليل أي نتيجة، مثلاً من SSRF→IMDS أو من فاحص الأسرار) ⟵ لو فيه ملف IAM، نحلّل تصعيد الصلاحيات الممكن بيها.

الأداة بتتابع أي (فاحص، أصل) اشتغل بالفعل عشان الـ follow-up ما يعيدش نفس الاختبار؛ واللي مالوش هدف جاهز يتشغّل تلقائيًا بيتعرض كـ **توصية (recommend)** للمحلّل.

### 7) الربط والترتيب (Correlation / dedup + risk scoring) + طبقة الـ ML الخفيفة
قبل العرض أو الكتابة بيعدّي على ٣ مرّات خفيفة في `_finish`:
1. **collapse للمكرر تمامًا** بقواعد حتمية (`risk/rules_engine.py`).
2. **تجميع المتشابه القريب** (`risk/ml/dedup.py`).
3. **ترتيب وأولوية** (`risk/ml/ranker.py`) — وده المصدر الوحيد لترتيب الجدول والتقرير.

وفيه كمان طبقة **ML خفيفة** بتعمل فلترة للأصول الحيّة و dedup/ranking — مش موديلات تقيلة، لكن منطق خفيف عملي بيقلّل الضجيج ويرتّب حسب الخطورة. درجة الخطورة نفسها بتتحسب من severity × confidence (`risk/scoring.py`).

### 8) التقرير الموحّد + الإيميل الاختياري
التقرير بيتكتب بصيغة (أو صيغ) `--format`: **json** (الافتراضي، دايمًا موجود)، **html**، **sarif** — عبر الكتّاب في `report/` (`json_report.py`, `html_report.py`, `sarif_report.py`). الأسرار في الأدلّة بتتعمّى (redacted) افتراضيًا إلا لو اديت `--show-leak` (للعرض المتحكّم فيه بس). والصيغ غير الـ JSON بتتكتب جنب ملف `-o` بامتدادها الخاص. وعلى مستوى النشر، فيه Lambda اختيارية لإرسال التقرير بالإيميل (SES).

---

## الثغرات اللي بيكشفها — الـ 9 Scanners

كل الفاحصين في `src/wily/scanners/`، وكلهم **كشف/إثبات-مفهوم فقط (detection/PoC-only)** وبيحترموا الـ ScopeManager. تحت كل فاحص: إيه الثغرة، ليه خطيرة، وإيه التقنيات اللي بيعملها فعلًا (مأخوذة من أسماء التقنيات/الفئات في الكود).

### 1) `authz_bypass.py` — تجاوز تفويض الـ API + CORS (OWASP API2:2023)
**الثغرة:** في بيئات زي AWS API Gateway، كل route (مسار + method) مربوط بـ Authorizer مستقل، والخطأ الشائع مش تلاعب بالمسار، لكنه **عدم اتساق فرض التفويض بين الـ methods على نفس المورد**.
**الخطورة:** أي method بترجّع بيانات حسّاسة بدون تفويض = تسريب مباشر أو تجاوز كامل للمصادقة.
**التقنيات الفعلية في الكود:**
- `missing_authorizer`: أي method بترجّع بيانات (200/201) من غير أي Authorization header. وبيميّز "soft-200" (رد 200 نصّه رسالة خطأ تفويض) فما يحسبهوش تسريب، وبيأكّد الثقة بمقارنة الرد غير المصادَق مع الـ baseline المصادَق لو متاح.
- `authorizer_fail_open`: الـ route بيرفض غياب الهيدر (401/403) بس بيقبل **credential فاسد** (200) — ده الـ fail-open الكلاسيكي للـ Lambda authorizer أو سياسة wildcard مكاش (OWASP API2:2023).
- `method_inconsistency`: method محمية صح (مثلاً GET) و method تانية على نفس المورد مش محمية (مثلاً DELETE).
- (وفي نفس الملف كمان) `StageInconsistencyScanner`: تناقض بين الـ stages (prod محمي بينما dev/staging مكشوف).
- **CORS** (`CorsMisconfigScanner`): بيبعت Origin مزوّر ويشوف هل السيرفر بيعكسه في `Access-Control-Allow-Origin` مع `Access-Control-Allow-Credentials: true` (أخطر حالة)، أو `*` + credentials (حالة أقل خطورة).
الفحوصات الافتراضية **سلبية** (GET/HEAD بس)؛ فحص الـ methods المدمّرة (POST/PUT/DELETE/PATCH) **opt-in** ومحتاج تأكيد صريح لأنه ممكن يغيّر/يمسح بيانات حقيقية.

### 2) `bola.py` — Broken Object Level Authorization (الوصول عبر المستأجرين)
**الثغرة:** السيرفر بيتأكّد إن الـ session/JWT صالح، بس **مش بيتأكّد إن صاحب الطلب هو فعلًا مالك المورد** — فمستأجر يقدر يوصل لبيانات مستأجر تاني.
**الخطورة:** تسريب بيانات عبر المستأجرين (cross-tenant)، من أخطر ثغرات الـ APIs.
**التقنيات الفعلية:** بياخد **هويتين أو أكتر** (`--identity`) ويعيد **نفس الطلب** بهوية مختلفة ويقارن الردود بأكتر من إشارة (مش status code بس): تطابق الـ status، فرق الحجم، **تشابه بنية الـ JSON (Jaccard على مسارات المفاتيح)**، و"سنيفر" لرد 200 اللي جسمه رسالة رفض. بيطلّع درجة ثقة HIGH/MEDIUM/LOW.
فيه تمييز ذكي بين ٣ أنواع مرشّحين: **owned** (هوية معروفة ملكيتها بالمراقبة — ممكن توصل HIGH)، **seeded** (مُستنتجة من claims الـ JWT زي `sub`/`user_id` لتعبئة قوالب زي `/users/{id}` — سقفها MEDIUM)، و**unowned** (مفيش مالك — سقفها MEDIUM). وبيعمل **٣ عيّنات baseline للمالك** عشان يستبعد الحقول المتقلّبة (timestamps/nonces) ويتحقّق من استقرار الـ baseline قبل ما يحكم. الإعادة GET/HEAD بس افتراضيًا، والـ methods المدمّرة محتاجة إذن.

### 3) `jwt_tamper.py` — التلاعب بالـ JWT (≈٨ تقنيات)
**الثغرة:** ضعف في التحقق من توكنات JWT يسمح بتزوير هوية/صلاحيات.
**الخطورة:** انتحال كامل لأي مستخدم/أدمن.
**التقنيات الفعلية (كل واحدة category خاصة بيها):**
- `alg_none`: تحويل `alg` لـ `none` بكل تنويعات حالة الأحرف (none/None/NONE/…) مع إزالة التوقيع.
- `signature_stripped`: نفس الهيدر/الحمولة والتوقيع متشال.
- `jwk_header_injection`: توليد مفتاح RSA محلي وحقن المفتاح العام داخل هيدر `jwk` — يكشف سيرفر بيثق في مفتاح مُرفَق بالتوكن.
- `rs256_hs256_confusion`: توقيع HS256 باستخدام المفتاح العام RS256 كسرّ HMAC (محتاج `known_public_key_pem`).
- `jku_header_injection`: حقن رابط canary في هيدر `jku` وإثبات الثغرة بـ **OOB callback** حقيقي (لو canary شغّال — `--blind`).
- `kid_null_key`: تلاعب بـ `kid` كمسار ملف (path traversal لملف فاضي زي `/dev/null`) مع توقيع بمفتاح فاضي (تقنية jwt_tool موثّقة).
- `expiry_claim_analysis`: فحص سلبي للـ claims — هل فيه `exp`، هل منتهي لكنه مقبول، وهل العمر الافتراضي طويل أوي (> ٢٤ ساعة).
فيه حارس مهم: الفاحص الأول بيتأكّد إن الـ endpoint بيرفض الطلب بدون أي auth، وإلا يبقى مش محمي بـ JWT أصلًا ويوقف قبل أي اختبار تزوير (تفادي false positives).

### 4) `ssrf_imds.py` — SSRF على خدمة الميتاداتا السحابية (IMDS)
**الثغرة:** تخلّي السيرفر يجلب موارد داخلية نيابةً عنك، وأخطرها الوصول لـ **IMDS** (`169.254.169.254`) لسحب credentials الـ IAM role بتاع السيرفر — نفس شكل حادثة Capital One.
**الخطورة:** سرقة مفاتيح سحابية = سيطرة على موارد الحساب.
**التقنيات الفعلية:**
- `v1-direct` (IMDSv1): سلسلة حقيقية من خطوتين — قراءة اسم الـ role ثم جلب الـ credentials باسمه.
- `ip-bypass`: نفس السلسلة بترميزات IP بديلة لتفادي فلاتر الـ WAF السطحية: **decimal، hex، nip.io، IPv6-mapped (نقطي وبصيغة hex-word)**.
- `imdsv2-put-get-chain` (المستوى 3): سلسلة PUT للـ token ثم GET بالهيدر — بتتشغّل بس لو الـ endpoint بيسمح بالتحكم الكامل في method/headers.
- `blind_ssrf_oob` (المستوى 4، عبر `--blind`): لمّا الرد ما بيرجعش للمستخدم، الإثبات الوحيد إن السيرفر فعلًا عمل طلب خارجي — بيتأكّد عبر **OOB canary** محلي.
الدليل مش status code بس: بيتأكّد من ظهور علامات حقيقية (`AccessKeyId`/`SecretAccessKey`) بعد اكتمال السلسلة، والأدلّة بتتعمّى (sanitize) من المصدر. الفاحص `requires_owned_infra=True` ومحتاج `--confirm-owned-infra` (افتراضيًا شغّال في `scan`).

### 5) `iam_privesc.py` — تصعيد صلاحيات IAM (كتالوج Rhino Security Labs)
**الثغرة:** صلاحيات IAM زيادة عن اللزوم تسمح لمستخدم/role إنه يرفّع صلاحياته لحد الأدمن.
**الخطورة:** السيطرة الكاملة على حساب AWS.
**مميّز:** الفاحص ده **مفيش فيه أي HTTP** — مدخله ملف واحد من أمر قراءة فقط: `aws iam get-account-authorization-details` (نفس مصدر PMapper). بيبني **جراف اتجاهي (networkx)** للصلاحيات ويحلّل مسارات التصعيد.
**التقنيات الفعلية (من كتالوج Rhino الـ 28):**
- **Self-mutation** (الطرق ١–١٣): صلاحيات زي `iam:PutUserPolicy`, `iam:AttachUserPolicy`, `iam:CreatePolicyVersion`, `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:AddUserToGroup`… اللي بتخلّي الـ principal يوسّع صلاحياته بنفسه.
- **PassRole + خدمة**: `iam:PassRole` مع خدمة تانية للوصول لـ role أقوى عبر: **EC2، Lambda، Glue، ECS، CloudFormation، DataPipeline، SageMaker، CodeStar**.
- **Trust-Policy Abuse** (الطريقة ١٤): `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` معًا — إعادة كتابة trust policy لـ role عشان يثق فيك ثم تتقمّصه.
- **Resource Hijack** (صلاحية واحدة): `lambda:UpdateFunctionCode` (#18)، `lambda:UpdateFunctionConfiguration` (#26)، `glue:UpdateDevEndpoint` (#20)، `sagemaker:CreatePresignedNotebookInstanceUrl` (#28)، `codestar:CreateProjectFromTemplate` (#23) — الاستيلاء على مورد قائم ووراثة الـ role المربوط بيه بدون PassRole.
بيحلّ الصلاحيات من الـ policies المضمّنة (inline) والمُدارة (managed) المرفقة، وبيحترم نطاق حسابات AWS. ملاحظة إصدار: v0.1 لسه ما بتحسبش Explicit Deny/SCP/Permissions Boundary — فمكتوب caveat في كل نتيجة للمراجعة اليدوية.

### 6) `s3_bucket.py` — سوء إعداد S3 buckets
**الثغرة:** buckets مكشوفة للعامة (قراءة/سرد/كتابة).
**الخطورة:** تسريب بيانات، وفي حالة الكتابة: تشويه/استضافة ملفات خبيثة/تدمير بيانات.
**التقنيات الفعلية (كلها GET — قراءة فقط):**
- `s3-bucket-public-listing`: سرد مجهول للـ bucket (رد فيه `<ListBucketResult>`).
- `s3-bucket-public-object`: قراءة object معروف بدون credentials.
- `s3-bucket-public-acl`: الـ ACL/policy نفسه مقروء مجهولًا ويمنح `AllUsers`/`AuthenticatedUsers`.
- `s3-bucket-public-writable` (اختياري عبر `--confirm-s3-writes`): **استنتاج** قابلية الكتابة من منحة `WRITE`/`WRITE_ACP` في الـ ACL — **من غير ما يبعت أي PUT/DELETE خالص**.
الفاحص آمن بالتصميم: بيقرأ الـ ACL بس ويستنتج، وما بيعملش أي عملية تعديل على أي bucket تابع لطرف تالت.

### 7) `cloud_storage.py` — تعداد التخزين السحابي (بأسلوب cloud_enum)
**الثغرة:** buckets/حاويات مكشوفة أو موجودة عبر AWS/Azure/GCP ممكن تتخمّن بأسماء مشتقّة.
**الخطورة:** اكتشاف تخزين عام أو موجود يخصّ الهدف.
**التقنيات الفعلية (كلها GET):** بياخد اسم مرشّح (مولّد من كلمة مفتاحية + تحويرات في `recon/cloud_enum.py`) ويفحص:
- **AWS S3**: `https://{name}.s3.amazonaws.com/` — 200 = مفتوح، 403 = محمي (موجود)، 404 = مش موجود.
- **Azure Blob**: وجود الحساب على `{account}.blob.core.windows.net`، ثم تخمين الحاويات المفتوحة عبر `?restype=container&comp=list`.
- **GCP**: `https://storage.googleapis.com/{name}` — بنفس منطق 200/403/404.
أي **AWS bucket** بيظهر هنا بيتسلّم تلقائيًا للفاحص العميق `s3_bucket` (الـ "auto → S3 scanner" hand-off). بيتفعّل عبر `--cloud-enum` ومدفوع بكلمة مفتاحية فبيشتغل حتى من غير أي HTTP endpoints.

### 8) `secret_scan.py` — كشف تسريب المفاتيح والأسرار (كشف فقط)
**الثغرة:** credentials طويلة العمر مزروعة في bundles الـ JS، أجسام الردود، أو ترافيك مُستورَد.
**الخطورة:** مفتاح سحابي مسرّب = وصول مباشر لموارد.
**التقنيات الفعلية:** بيدوّر على **أشكال الأسرار** في النص اللي عند الماسح أصلًا (JS + ترافيك Burp/HAR + توكنات ملاحَظة). بيكتشف: `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`, `private_key`, `github_token`, `slack_token`, `google_api_key`, `jwt`, `bearer_token`, ومفاتيح عامة — مع severity/confidence لكل نوع.
**مهم:** **كشف فقط ولا يُستخدَم** — ما بيصادقش على أي خدمة بالمفتاح؛ التقرير بيحتفظ بمؤشّر **مقنّع (masked)** للسرّ مش القيمة الخام، فالنتيجة قابلة للتنفيذ من غير إعادة تسريب.

### 9) `takeover.py` — الاستيلاء على النطاقات الفرعية (Subdomain Takeover)
**الثغرة:** سجل DNS معلّق (dangling): subdomain لسه `CNAME` بتاعه بيشاور على خدمة سحابية اتلغت — فمهاجم يعيد تسجيل المورد ويخدّم محتوى من subdomain الضحية.
**الخطورة:** انتحال النطاق، phishing، سرقة جلسات/ثقة.
**التقنيات الفعلية (رصد + بصمة فقط):** بيقارن إشارتين آمنتين: الـ `CNAME` ضد لواحق مزوّدين معروفين، وجسم الرد ضد **بصمة "غير مُطالَب بيه"** للمزوّد. بيغطّي ~٩ خدمات: **AWS S3، GitHub Pages، Heroku، Fastly، Azure، CloudFront، Shopify، Bitbucket، Pantheon**. بعض الخدمات تتأكّد بالبصمة وحدها (زي `NoSuchBucket` من S3 اللي ما بيتلبسش)، والباقي بيحتاج الـ CNAME كمان لتفادي 404 عادي. **ما بيسجّلش ولا بيطالب بأي مورد** — بيرصد مؤشّر بس للمحلّل يأكّده ويطالب بالمورد دفاعيًا.

---

## التثبيت والاستخدام

### التثبيت
الأفضل عبر **[pipx](https://pipx.pypa.io)** لأنه بيثبّت أمر `wily` في بيئة معزولة وبيحطّه على الـ `PATH`:

```bash
pipx install git+https://github.com/mostafaa23/AuthTrust.git
```

أو بـ `pip` عادي (يفضّل جوّا virtual environment):

```bash
pip install git+https://github.com/mostafaa23/AuthTrust.git
```

في الحالتين بتحصل على أمر **`wily`** في التيرمينال. مطلوب **Python 3.11 أو 3.12**.

```bash
wily --version
wily -h
```

### الاستخدام
```bash
# الحزمة الكاملة تلقائيًا: discovery + auth bypass + CORS + SSRF
wily scan example.com -o report.json
```

```bash
# إضافة فحص JWT (محتاج توكن صالح)
wily scan example.com --token eyJhbGciOi... -o report.json
```

```bash
# إضافة BOLA (محتاج هويتين على الأقل للمقارنة)
wily scan example.com \
  --identity tenant_a="Bearer xyz" \
  --identity tenant_b="Bearer abc"
```

```bash
# تحليل تصدير IAM لتصعيد الصلاحيات (من غير دومين)
wily scan --iam-file authorization-details.json
```

```bash
# تعداد التخزين السحابي + تقارير HTML و SARIF جنب الـ JSON
wily scan example.com --cloud-enum -o report.json --format html,sarif
```

```bash
# استيراد ترافيك بدل/بجانب الاكتشاف الحيّ
wily scan example.com --burp-xml items.xml
wily scan example.com --import-har capture.har
```

وكل محرّك متاح لوحده كـ subcommand مستقل (الأوامر الموجودة فعلًا):
```bash
wily jwt <url> --token TOKEN_VALUE   # فحص JWT فقط
wily authz <url>                     # فحص Auth Bypass فقط
wily iam authorization-details.json  # تحليل IAM فقط
wily ssrf <url> --param url           # فحص SSRF/IMDS فقط
wily discover <domain>                # اكتشاف الـ endpoints فقط، بدون فحص
```

شغّل `wily <command> -h` لكل خيارات أي أمر فرعي.

بعض الخيارات المفيدة على `scan`: `--blind` (SSRF أعمى عبر canary)، `--allow-local` (اختبار محلي)، `--no-destructive` (إيقاف فحوص الكتابة)، `--no-owned-infra` (إيقاف SSRF/IMDS)، `--confirm-s3-writes` (الإبلاغ عن قابلية كتابة S3 المستنتجة)، `--probe-live` (رمي الـ endpoints الميتة)، `--scope-bucket`/`--scope-account`/`--scope-config` (ضبط النطاق)، `--show-leak` (كتابة الأدلّة بدون تعمية — للعرض المتحكّم فيه فقط).

---

## ملاحظة أمان وأخلاقيات

Wily أداة **موجّهة للكشف (detection/PoC-only)** ومخصّصة للاختبار **المصرّح به فقط**.

- بتفرض **نطاق (scope)** صارم وبترفض الـ hosts اللي برّه؛ العناوين المحلية محتاجة `--allow-local` صريح.
- فحوصات S3 والتخزين السحابي **قراءة فقط** — بتقرأ الـ ACL/policy وما بتبعتش `PUT`/`DELETE`، فما تقدرش تكتب أو تمسح أي object.
- السلوكيات العدوانية **opt-in وموضّحة**: فحوص الكتابة في التفويض (`--no-destructive` للإيقاف)، فحص SSRF/IMDS (`--no-owned-infra` للإيقاف)، والـ blind SSRF (`--blind`).
- فاحص الأسرار **كشف فقط** وما بيستخدمش أي مفتاح لمصادقة أي خدمة؛ والأسرار في التقارير **معمّاة افتراضيًا**.
- كل الفاحصين **PoC/كشف فقط** وبيحترموا الـ ScopeManager — مفيش أفعال مدمّرة ضد أهداف طرف تالت.

**شغّل Wily فقط على أنظمة تملكها أو عندك إذن مكتوب وصريح باختبارها.**

</div>
