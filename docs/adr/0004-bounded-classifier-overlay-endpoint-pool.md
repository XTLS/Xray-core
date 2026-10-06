# ADR-0004: Ограниченный pool private classifier endpoint

- Status: Accepted
- Date: 2026-10-01; уточнение recovery: 2026-10-07
- Repo-owner: `evasionlab/Xray-core`
- Consumers: `evasionlab/XrayR`, `vpn.infra`, `dns-route-cache`; `vpn.bot` сохраняет logical routing owner.
- Org-wide record: `evasionlab/infra/docs/adr/ADR-20261001-01-dns-cache-first-connection-and-l1-persistence.md`, дополнение owner о шести colocated classifier с общим L2.
- Implementation: уточнение принято для source-разработки; не Rolled. Canary207 с validity fix прошёл обычные traffic gates, но проверка central endpoint loss выявила исчерпание бюджета известным failed probe. Fleet остаётся HOLD; исправление probe требует отдельного artifact/canary evidence.
- Org-wide recovery contract: `evasionlab/infra/docs/architecture/kolmogorov-ha-data-consumer-contract-20261006.md`.

## Контекст и проблема

Private `/v1/classify` доступен через один operator-pinned NetBird endpoint.
При его отказе L1 продолжает работать до своих deadlines, но cold lookup не
получает готовый L2. Новый общий proxy снова создал бы отдельную точку отказа;
proxy на каждом VPN узле добавил бы новый процесс и жизненный цикл.

## Решение и контракт

Core выполняет ограниченный failover напрямую на operator-pinned pool. Runtime
JSON, protobuf и classifier body `{domain, allowStale}` сохраняются. Клиентские
IP/DNS answers не участвуют в выборе route. `XrayR` меняет только exact source
endpoint существующим overlay mapping, после чего core использует pool только
у matcher с effective endpoint, равным singular overlay pin.

`XRAY_ASYNC_DNS_OVERLAY_ENDPOINTS_JSON` — JSON-массив 2–6 уникальных URL, до
4096 bytes. Каждый URL — canonical literal private IP или NetBird `100.64/10`,
HTTP, явный numeric port 1–65535 и точный `/v1/classify`; нет loopback, hostname,
credentials, query, fragment или escaped path. Первый элемент строго равен
`XRAY_ASYNC_DNS_OVERLAY_ENDPOINT`; `XRAY_ASYNC_DNS_OVERLAY_SOURCE_ENDPOINT`
остаётся точным исходным HTTPS URL. Отсутствующий или пустой plural env сохраняет прежний
single-endpoint transport. Непустое некорректное значение или
pool без source mapping/token отклоняет startup/reload, а не включает fallback.

Один защищённый существующий token file используется всеми classifier. Auth
допустим только точному immutable allowlist pool; transport не использует
environment proxy, DNS или redirects. Ошибка private pool не переключает
автоматически на публичный logical endpoint. Узкая overlay ACL и фактический
маршрут каждого pin через encrypted overlay проверяются rollout owner.

Каждая shared domain job выбирает rotating start; максимум шесть последовательных
backend попыток, по одной на eligible configured member, пока не истёк общий
deadline. `requestTimeoutMillis` ограничивает **всю операцию**, не каждую попытку
по отдельности. При configured 150 мс здоровый первый member получает все
оставшиеся 150 мс: бюджет больше не делится на число healthy/eligible members.
После быстрого transport failure или HTTP 502/503/504 следующий eligible member
получает только оставшееся время того же deadline. Отдельных concurrent/hedged
запросов нет. Pending, ready other, stale и любой неретраибельный HTTP/invalid
payload завершают операцию; 401/403/429 не вызывают fanout.

Если первый member молча завис, он может исчерпать одну фоновую операцию.
Она завершается ошибкой в общем deadline; retryable timeout записывает passive
cooldown **до** возврата даже при истёкшем parent deadline. Следующая eligible
операция может выбрать выжившего. Это не обещание успешного failover в той же
операции и не гарантия zero errors или recovery меньше 150 мс. Явная внешняя
cancellation/Close прекращает попытки без ложного health penalty.
Первый `firstDone` закрывается после всей операции, не после первой backend
ошибки. Общий worker/job/retry admission остаётся конечным. Core не добавляет
Redis writes, SET replay или повтор side effects: прежний domain-only classifier
body и серверные lease/fill fences сохраняются.

Passive endpoint cooldown 250 мс–5 с хранит максимум шесть состояний отдельно
от cache mutex. Уже известные failures пропускаются; полностью cooling pool
сразу завершает операцию ошибкой. Общий classifier cooldown учитывает результат
операции целиком. Нет дополнительных probe goroutines или health HTTP traffic.
Low-cardinality stats: pool size, attempts, failovers, cooldown skips; нет URL,
domain, token или user labels.

**Caller `routeWaitMillis` остаётся независимым общим бюджетом выбора маршрута**
по ADR-0003. Canary207 имеет actual routeWait0; это значение не меняется.
Иные configured waiter budgets тоже сохраняются. Холодный connection продолжает
существующий static/default fallback; valid L1 и bounded stale grace остаются
рабочими. Worker может завершиться позже и наполнить L1 для следующих connections.
Recovery включает существующие per-domain retries 250 мс–5 с с jitter, shared
failure cooldown после трёх failures до 5 с, scheduler 25 мс и domain total budget
30 с. Эти пределы не меняются; elapsed recovery доказывается реальным canary,
а не прямым `fetch` или readiness. Не обещается immediate next job.

### Повторная попытка известного failed endpoint

После passive cooldown endpoint с существующим `failures > 0` остаётся
известным failed probe. Если после него в текущем списке есть ещё не
пенализированный candidate, только такой probe получает child deadline
`min(50 мс, remaining / 2)` внутри прежнего shared deadline. Если child budget
меньше 1 мс, probe пропускается без HTTP и нового health penalty. Timeout child
демотирует endpoint, но живой parent позволяет попробовать successor в той же
операции. Explicit parent cancellation не создаёт дополнительный health penalty.
Never-failed endpoint и случай без доступного unpenalized successor сохраняют
весь remaining budget; healthy3×80 мс и общий150 мс не меняются.

Последствие: восстановившийся known endpoint с ответом80 мс может оставаться
пенализированным, пока есть здоровые peers; не обещается восстановление каждого
member через короткий probe. Если все candidates penalized, полный remaining
budget позволяет восстановить и медленный member. Новых фоновых probes,
workers, retry schedules, flags или расширения request/routeWait budgets нет.
Первый неизвестный silent отказ по-прежнему может завершить background job
ошибкой; valid L1, stale grace и routeWait0 fallback сохраняют прежний контракт.

## Cache semantics

Snapshot identity связывает отсортированный endpoint set, owner-managed
`snapshotCompatibilityId` и прежние maxTTL/SWR limits. Перестановка и выбор
backend не сбрасывают L1; изменение состава pool или semantic namespace
инвалидирует restore. Reload с тем же protobuf config дополнительно проверяет
effective transport identity, чтобы изменённый process env не наследовал
старый cache/job state. Compatible reload сохраняет passive cooldown deadlines.
Token не участвует в snapshot identity. Absolute TTL и elapsed subtraction
включают все попытки; failover/restart не обновляют срок классификации.

Шесть classifier должны обслуживать **один фактический Redis namespace** с
одинаковыми GeoIP content hash, resolver view/upstreams и TTL/SWR semantics.
Текущий response не несёт namespace, поэтому startup namespace/readback является
обязательным owner evidence перед canary, а не автоматической проверкой core.

## Проверка и rollout

Focused HTTP tests используют private pins с loopback DialContext seam и fake
token; production loopback pin не разрешается. Проверяются ready failover в
одной shared operation после fast refusal, healthy3×80 мс при общем150 мс,
silent first→одна bounded failure→cooldown→следующая eligible operation,
all-blackhole150/200 мс с одной попыткой и сохранённым cooldown,
отмена без ложного health penalty, max6/общий timeout, независимый25 мс waiter
и actual scheduler recovery при routeWait0 с сохранением warm L1/deadlines, отсутствие fanout при pending/auth/429/redirect/invalid response,
bounded concurrent health state, proxy/token allowlist и snapshot/reload
совместимость без продления TTL. Старые TTL/SWR/wait tests сохраняются.

`XrayR` рекламирует `async-dns-route-endpoint-pool-v1` отдельно от
`async-dns-route-cache-v2`. Старый образ может игнорировать plural env, поэтому
его наличие не доказывает HA: canary требует capability, точный image, overlay
readback и реальный failover. Начальный pool может содержать Iris и прежний
central classifier; целевой pool — шесть DNS узлов. Fleet expansion не разрешена
этим ADR автоматически. Snapshot namespace проверяется вновь перед включением.

## Альтернативы и последствия

DNS round-robin не даёт bounded отказа текущего backend. Новый central proxy
создаёт дополнительный отказ; local proxy добавляет lifecycle на каждом XrayR.
Шесть параллельных RPC и hedging отвергнуты: amplification и дополнительные
запросы до authoritative pending/auth ответа. Равные короткие shares тоже
отвергнуты: три здоровых80 мс endpoints отбрасывались при150 мс logical budget.
Увеличение общего timeout или routeWait маскирует проблему и не принято.
Sequential full-remaining сохраняет здоровые ответы, но явно допускает одну
failed background operation при silent первом endpoint; последующий recovery
ограничен прежними retries и проверяется canary.

Максимальное число backend calls на shared operation увеличивается с одного до
шести без увеличения общего HTTP deadline; фоновые domain retries по-прежнему
ограничены восемью. При холодном L2,
queue pressure или отказе pool connection продолжает static/default rules.
Rollback удаляет plural env и сохраняет singular pin либо возвращает прежний
immutable image через текущего writer; публичный HTTPS rollback выполняется
явным удалением overlay mapping и pool env. Tokens/L2/snapshots удалять не нужно.
