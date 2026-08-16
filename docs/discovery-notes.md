# PortProof — Discovery Notes

## المشكلة المرصودة
المطورون وسكربتات CI/CD يحتاجون فحص منافذ محلية وبعيدة (قواعد بيانات، خدمات داخلية، healthchecks) قبل تنفيذ خطوات لاحقة. الأدوات الشائعة:

| أداة | ضعفها |
|---|---|
| `wait-for-it.sh` (5.8k stars) | نص bash واحد، لا JSON، سطر واحد فقط لكل invocation، لا تحقق طبقة تطبيق (TLS/HTTP banner)، مخرجات نصية غير قابلة للتحليل |
| `nc -z -w` | سلوك غير متناسق عبر الأنظمة (timeout لا يعمل reliably في بعض إصدارات netcat — انظر SO 24198456)، لا JSON |
| `nmap` | ثقيل، يتطلب root أحيانًا، مصمم للـ scanning لا للـ verification في CI |
| `docker wait` / compose `service_healthy` | مربوط بدوال Docker، لا يعمل خارج compose، لا يخرج دليلًا |
| `telnet` | hangs دون timeout واضح (SO 4922943) |
| Python one-liners عبر forums | لا reusable، لا exit code discipline، لا retries |

## Who / Why / Gap
- **من**: مطورو DevOps/CI، أصحاب compose stacks، مشغّلو runbooks، أتمتة AI agents تحتاج structured output.
- **كيف الآن**: bash loops + nc/telnet + grep — مخرجات نصية هشة، exit codes غامضة، لا سجل تدقيق.
- **الفجوة**: لا توجد أداة بلا تبعيات، متعددة الأهداف في سطر واحد، مع (1) JSON evidence حتمي قابل للتدقيق، (2) فحص اختياري بطبقة تطبيق (TLS handshake / HTTP probe)، (3) exit code discipline موثقة (0 = كل الأهداف مفتوحة)، (4) retries مع backoff قابل للتكوين لكن بدون انتظار غير محدود افتراضيًا.

## Project Thesis
For CI and DevOps engineers who need to gate steps on service readiness, PortProof provides a zero-dependency CLI that verifies local and remote TCP ports with deterministic JSON evidence and application-layer probes (TLS/HTTP), unlike wait-for-it/nc, by emitting machine-verifiable proofs with strict exit-code discipline.

## Differentiators (Structural)
1. **JSON Evidence Mode**: كل فحص يخرج `{host, port, protocol, status, reason, elapsed_ms, deadline_iso, attempt}` — دليل قابل للتدقيق، لا نص ملون فقط.
2. **Batch Determinism**: عدة أهداف في سطر واحد + `--fail-mode` (any|all) + report واحد شامل بدل سلسلة commands.
3. **Application-layer optionality**: TCP فقط افتراضيًا (آمن)، TLS handshake / HTTP probe اختياري صريح — لا مفاجآت network.
4. **CI exit codes**: 0 = pass، 1 = هدف واحد على الأقل فشل، 2 = input/validation error — موثق بجدول.
5. Zero dependencies، Python stdlib فقط.

## الأخطار (Threat Model مبدئي)
- port scanning غير مقصود → default: TCP فقط، بلا UDP، بلا service discovery.
- output injection في JSON → host/port يتحقق منهما قبل الإخراج (strict validation).
- infinite waits → default: deadline قصير (5s) بدون --wait loop؛ wait loop يتطلب --deadline صريح.
- path traversal/unsafe files لا ينطبق (لا قراءة ملفات) لكن report file path يجب رفض relative خارج cwd.

## قرار النطاق (Must/Should)
- Must: TCP check متعدد الأهداف، JSON evidence، exit codes، timeouts، batch report، validation صارمة.
- Should: TLS handshake probe، HTTP HEAD probe، --wait (loop) مع backoff محدود.
- Could: UDP (مستبعد من v1)، service banner.
- ملاحظة: --wait بلا deadline افتراضي = خطر hang؛ نجعل --wait يتطلب --deadline.
