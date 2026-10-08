# ADR-0003: Ограниченное ожидание L2, персистентный L1 и LRU

- Status: Rolled
- Date: 2026-10-01
- Repo-owner: `evasionlab/Xray-core`
- Downstream consumers: `evasionlab/XrayR`, `vpn.bot`, `vpn.infra`, `evasionlab/dns-route-cache`, клиентские DoH backend.
- Org-wide ADR required: Yes.
- Org-wide ADR: `evasionlab/infra/docs/adr/ADR-20261001-01-dns-cache-first-connection-and-l1-persistence.md` — канонический общий контракт, подготовлен вместе с этим документом.
- Implementation status (2026-10-08): cache-v2 принят на 89 XrayR-процессах / 105 ID: bounded L2 wait, persistent L1 storage и canonical6 transport подтверждены owner ACK и свежей serving-сверкой. Клиентская часть общего ADR имеет отдельные gates.

## Контекст

[ADR-0001](0001-async-shared-dns-route-cache.md) гарантирует неблокирующий L1
match, TTL/SWR и ограниченное фоновое обновление. В core `c5b6701db2d6`
первый L1 miss немедленно даёт false даже при ready/ru в L2. Рестарт теряет
кэш, а capacity eviction после удаления expired записей выбирает произвольный
элемент map. Reload идентичной конфигурации уже наследует состояние в памяти.

## Проблема

Тёплый общий cache не помогает текущему connection, и полезная информация
теряется при рестарте или произвольном вытеснении. Полный DNS resolve в пути
маршрутизации остаётся недопустимым.

## Решение

Общий ADR заменяет только безусловно nonblocking miss-контракт ADR-0001:

1. На L1 miss разрешено ограниченное ожидание готового ответа `/v1/classify`.
   Первый canary budget 25 мс, default 0 сохраняет прежний режим. Это общий
   бюджет одного route selection, включая queue/admission; не 150 мс фонового
   HTTP timeout и не ожидание DNS. Ready ru применяется к текущему connection;
   ready other кэшируется и возвращает false. Pending/error/timeout продолжают
   правила. Stale подчиняется прежним opt-in и исходному hard deadline.
2. Существующая in-flight задача домена разделяется между waiters. Нет второго
   параллельного RPC только из-за синхронного режима, неограниченной очереди
   либо I/O под cache mutex. Поздний ответ пополняет L1, но не перенаправляет
   уже созданный connection. Cancel waiter не отменяет общую задачу.
3. L1 получает background snapshot writer на постоянном XrayR volume: dirty
   snapshot не чаще 30 секунд с jitter, atomic replace, bounded размер и
   startup/shutdown budget. Сохраняются ru/other, generation, исходные deadlines,
   refresh metadata и LRU; не сохраняются tokens, users, HTTP и retry contexts.
   При restore обязательны schema/owner-managed compatibility identity,
   проверка возраста и hard expiry. Рестарт не обновляет TTL/grace. Непригодный
   файл даёт пустой L1 и не блокирует запуск.
4. Map + linked list обеспечивают O(1) LRU lookup/touch/victim removal.
   Пользовательский hit делает запись MRU; background reread не поднимает её
   популярность. Bounded cleanup удаляет expired, затем capacity вытесняет LRU.
   Нет полного scan под mutex на каждом miss; freshness проверяется независимо
   от своевременности cleanup. Capacity canary остаётся 4096.

SWR, generation anchoring, network elapsed subtraction, hard deadlines,
конечные retries/backoff/cooldown и порядок статических правил сохраняются.
Snapshot compatibility identity должна отражать effective classifier context,
resolver view/GeoIP namespace и локальную семантику. Её поставка принадлежит
owner-конфигурации, а не эвристике по совпадению hostname.

### Конфигурация source implementation

Новые поля `asyncDnsRoute`: `routeWaitMillis` (default 0, max 100),
`maxWaiters` (default 256, max 4096), `snapshotPath` (пустой выключает snapshot),
`snapshotCompatibilityId` (обязательный owner namespace при включении snapshot,
1–256 печатных ASCII bytes без пробелов). Unknown fields отклоняются.
Path — абсолютный clean путь до отдельного файла, уникальный для matcher/process;
пример `/var/lib/xrayr/dns-cache/primary.json` на постоянном volume.
ID должен включать runtime process и версию совместимой resolver/GeoIP view.
Core дополнительно связывает файл с effective endpoint и maxTTL/SWR semantics.

Snapshot writer работает каждые 30–33 секунды при dirty state. Restore ограничен
250 мс, 8 MiB и меньшим из cache capacity/4096; ожидание writer при Close —
250 мс. Per-path TryLock сохраняет один файловый I/O даже при медленном disk и
reload. Reload наследует абсолютные deadlines, LRU, jobs и classifier cooldown;
HTTP contexts и completion channels остаются у своих workers.
Счётчики wait/expiration/snapshot/restore доступны в low-cardinality stats.
Snapshot storage требует POSIX file permissions; попытка включить его на Windows
отклоняется явно. Bounded wait/LRU доступны независимо от storage.

DoH warm API, producer admission/auth и canonical DNS fill принадлежат
`dns-route-cache` и общему ADR. Core не принимает непроверенные DNS-ответы
клиента, не подключается к Redis и не копирует весь L2 при старте.
Bulk startup hotset, L2 active prefetch и SLRU не входят в первый выпуск.

Общий scope дополнен принятым DoH-only переходом managed client profiles:
`vpn.bot` убирает DoQ из новой выдачи, infra обеспечивает основной и независимый
резервный DoH-вход, прогрев L2 выполняется в DoH path. DoQ HA не строится;
серверные DoQ listeners сохраняются для старых профилей на переходный период.
Это изменение клиентской выдачи не меняет cache/matcher контракт core.
Bootstrap, direct/local transport и системный Tunnel DNS проверяются отдельно;
широкое direct-исключение всей зоны clodns.org не принимается автоматически.

## Проверка

- Первый connection при L1 miss/L2 ready RU, other caching, pending/timeout.
- Один RPC при нескольких waiters; общий deadline, cancellation и shutdown.
- Сохранение всех TTL/SWR тестов ADR-0001, включая expired-in-transit и смену RU→other.
- Graceful/kill -9 restart; corrupt/full disk; истёкший/несовместимый snapshot;
  clock rollback; отсутствие disk I/O в route path.
- Hotset и одноразовые домены за capacity: LRU order, bounded память и mutex latency.
- Exact pinned XrayR, runtime ACK и реальные cold/warm/post-TTL клиентские запросы.

Численные canary bounds, метрики, DoH-before-VPN proof и phased delivery заданы
общим ADR. Решение не разрешает rollout на весь fleet автоматически.

## Альтернативы

Always-nonblocking оставляет первый неверный маршрут; ожидание DNS возвращает
задержки IPOnDemand; полный L2 export создаёт startup burst; AOF каждого hit
добавляет ненужные disk writes. Выбраны bounded L2 read и периодический snapshot.

## Последствия и откат

L1 miss получает небольшой ограниченный latency, взамен ready L2 влияет на
первый connection. Появляются snapshot storage и waiters, но не новый routing
policy owner. Route-wait budget 0 возвращает прежнее поведение; snapshot можно
выключить независимо. При необходимости возвращается прежний CI artifact
через текущего writer. Общий L2 и snapshots не нужно очищать при rollback.


## Приёмка production 2026-10-08

Финальная сверка **13:34:07.733 UTC / 16:34:07.733 МСК** подтвердила
89/89 owner processes, canonical6 transport и cache-v2; 105 свежих Hello/enrollment.
Последний owner ACK — Planck/77 в 13:32:18.693 UTC. Источник:
`vpn/outputs/dns-cache-v2-finalize-20261008/owner-plan/final-audit-20261008T1334/accepted-scope.json`.
Persistent RW storage принят существующим guarded Ansible writer с root0700,
сохранением serving image/Cmd, unrelated config и статических rules/outbounds;
Planck отдельно получил согласованный bootstrap и один matcher перед catchall.
Process ACK не объявляется отдельным per-ID applied revision: такого поля нет.

Реально выданный VLESS TCP smoke ID77/224/233: 9/9 запросов, 283–366ms;
`vpn/outputs/online-state-fleet-rollout-20261007/cachev2-final-representative-20261008.json`.
Это representative proof, не проверка холодного RU решения на каждом ID и не
утверждение об отсутствии всех пользовательских failures. Namespace identity,
TTL/grace, cold25ms/background150ms budgets и static-rule precedence сохранены.
Клиентская promotion и испытание literal primary-IP outage резервного DoH
не входят в утверждение о завершённой серверной приёмке этого ADR.
