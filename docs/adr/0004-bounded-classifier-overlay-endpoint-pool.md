# ADR-0004: Ограниченный pool private classifier endpoint

- Status: Accepted
- Date: 2026-10-01
- Repo-owner: `evasionlab/Xray-core`
- Consumers: `evasionlab/XrayR`, `vpn.infra`, `dns-route-cache`; `vpn.bot` сохраняет logical routing owner.
- Org-wide record: `evasionlab/infra/docs/adr/ADR-20261001-01-dns-cache-first-connection-and-l1-persistence.md`, дополнение owner о шести colocated classifier с общим L2.
- Implementation: source подготовлен; production pool не включён.

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
остаётся точным исходным HTTPS URL. Отсутствие plural env сохраняет прежний
single-endpoint transport. Присутствующее пустое/некорректное значение или
pool без source mapping/token отклоняет startup/reload, а не включает fallback.

Один защищённый существующий token file используется всеми classifier. Auth
допустим только точному immutable allowlist pool; transport не использует
environment proxy, DNS или redirects. Ошибка private pool не переключает
автоматически на публичный logical endpoint. Узкая overlay ACL и фактический
маршрут каждого pin через encrypted overlay проверяются rollout owner.

Каждая shared domain job выбирает rotating start; максимум три последовательные
backend попытки. `requestTimeoutMillis` — общий HTTP deadline всей операции,
не по одному полному timeout на backend. Каждая попытка получает максимум
`timeout / min(3, poolSize)` (150 мс / 3 = 50 мс; 150 мс / 2 = 75 мс).
Cancellation/Close останавливают переключения. Pool retry разрешён только для
transport failures и HTTP 502/503/504. Pending, ready other, stale и любой
неретраибельный HTTP/invalid payload завершают операцию; 401/403/429 не вызывают
fanout. Первый `firstDone` закрывается после всей этой операции, не после
ошибки первого backend. Общий worker/job/retry admission остаётся конечным.

Passive endpoint cooldown 250 мс–5 с хранит максимум шесть состояний отдельно
от cache mutex. Уже известные failures пропускаются; полностью cooling pool
сразу завершает операцию ошибкой. Общий classifier cooldown учитывает результат
операции целиком. Нет дополнительных probe goroutines или health HTTP traffic.
Low-cardinality stats: pool size, attempts, failovers, cooldown skips; нет URL,
domain, token или user labels.

**Caller `routeWaitMillis` остаётся независимым общим бюджетом выбора маршрута**
по ADR-0003: canary 25 мс включает queue/admission. Worker может завершиться позже
и наполнить L1 для следующего connection. Blackholed первый backend с 50/75 мс
share не гарантирует текущему connection RU route; последующие запросы могут
пропустить backend по cooldown. Здоровые relay пути не получают новый 8 мс cutoff.

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
одной shared job, отмена, max3/общий timeout, независимый 25 мс waiter и позднее
наполнение L1, отсутствие fanout при pending/auth/429/redirect/invalid response,
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
Шесть параллельных RPC отвергнуты: amplification без необходимости.

Максимальное число backend calls на shared operation увеличивается с одного до
трёх; фоновые domain retries по-прежнему ограничены восемью. При холодном L2,
queue pressure или отказе pool connection продолжает static/default rules.
Rollback удаляет plural env и сохраняет singular pin либо возвращает прежний
immutable image через текущего writer; публичный HTTPS rollback выполняется
явным удалением overlay mapping и pool env. Tokens/L2/snapshots удалять не нужно.
