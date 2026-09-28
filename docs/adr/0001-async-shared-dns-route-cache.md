# ADR-0001: Асинхронная shared DNS route classification для edge Xray

Статус: Accepted
Дата: 2026-09-04

## Контекст

Часть Veesp downlink-узлов не имеет устойчивого пути к российским адресам.
Глобальный `IPOnDemand` позволял выбрать `direct-ru-egress-mark` по `geoip:ru`,
но сделал DNS синхронной частью критического пути каждого нового FQDN и вызвал
общую деградацию latency.

## Проблема

Нужно выбирать RU egress для уже известных российских адресов, не блокируя
первое соединение DNS-resolve и не заставляя каждый edge повторно выполнять
одинаковую классификацию домена.

## Принятое решение

`Xray-core` получает opt-in правило `asyncDnsRoute`.

- Rule match читает только bounded локальную L1-проекцию и никогда не ждёт
  сеть.
- На miss он возвращает `false`, поэтому побеждает существующий known-good
  default/Veesp rule, и ставит запрос в bounded async очередь.
- Background workers обращаются к shared L2 classifier-cache. L2 владеет
  distributed singleflight, DNS-resolve и TTL-классификацией `RU`/`other`.
- Только fresh `RU` entry делает rule match и выбирает уже настроенный
  `direct-ru-egress-mark` outbound. Ошибка, pending и unknown — fail-open в
  default route.
- В L2 не передаются user/device identifiers; domain state хранится не дольше
  TTL. Client-facing resolver публикует в L2 только нормализованные DNS
  результаты, без access logging.

`asyncDnsRoute` выключен по умолчанию: отсутствие config message не меняет
существующий routing.

### Service authentication (2026-09-05)

Для multi-edge public HTTPS classifier core поддерживает bearer из локального
файла, путь к которому задаётся `XRAY_ASYNC_DNS_BEARER_TOKEN_FILE`. Ansible
доставляет файл с mode `0600` и read-only mount; секрет не входит в runtime
payload/БД owner, URL или логи. Файл читается при создании matcher, поэтому
ротация требует restart/reload. Настроенный, но недоступный/пустой/некорректный
файл отклоняет новый matcher, а не включает anonymous fallback. Без env
сохраняется совместимость с первоначальным canary. Token отправляется только
HTTPS endpoint без URL credentials; redirects не выполняются. Проверка файла
и HTTP не добавляются в `Apply`, который остаётся nonblocking.

IP allowlist дополняет bearer, но не заменяет service authentication при
расширении. Секрет в runtime policy или URL отклонён из-за лишнего secret
distribution surface. mTLS остаётся альтернативой при появлении PKI lifecycle.

### Точный encrypted-overlay endpoint (2026-09-08)

Для согласованного NetBird пути оператор может задать
`XRAY_ASYNC_DNS_OVERLAY_ENDPOINT=http://100.75.19.209:8090/v1/classify`.
Это явное подтверждение оператором защищённого сетевого пути, не автоматическое
доверие private CIDR. Только буквальный IP с явным портом, без URL credentials,
query и fragment, и точное совпадение полного endpoint разрешают HTTP bearer.
Token file обязателен; ошибка конфигурации закрывает создание matcher. Имена
хостов запрещены для исключения DNS rebinding. HTTP_PROXY/HTTPS_PROXY не
используются для overlay, redirects запрещены при любом статусе.

Внешняя граница безопасности принадлежит `vpn.infra`/оператору: listener только
на NetBird IP, узкая peer policy edge→classifier на нужный порт, native bearer
проверка classifier, доказательство P2P и успешного classify после переключения.
Core не может доказать, что ОС отправляет этот IP через шифрованный туннель.
HTTPS остаётся default и rollback; наличие overlay opt-in не запрещает HTTPS.
XrayR наследует env процесса и точный core pin, схема runtime policy не меняется.
Новая transport boundary не расширяет набор клиентов; дальнейшее расширение
контролирует владелец rollout. Альтернатива — сохранить публичный Caddy/TLS;
отклонена для внутреннего пути из-за измеренной CPU нагрузки proxy. Цена
решения — перенос auth/listener/blue-green ответственности classifier/Ansible.

## Альтернативы

- Глобальный `IPOnDemand`: отклонён, так как блокирует route selection DNS.
- Local-only cache на каждом edge: отклонён, так как дублирует cold resolve и
  classification по fleet.
- Remote Redis/gRPC lookup из `PickRoute`: отклонён, так как вводит сеть в
  критический путь соединения.
- Runtime policy update на каждый DNS ответ: отклонён, так как создаёт storm в
  owner delivery и не имеет TTL/lifecycle semantics.

## Последствия

- Нужны HA L2 classifier-cache и два resolver endpoints; edge использует
  public HTTPS с service authentication, их outage не влияет на established
  known-good routing. Overlay остаётся management transport.
- XrayR передаёт только статический `asyncDnsRoute` config/capability. Он не
  владеет DNS-result state и не публикует runtime policy на каждый ответ.
- Rollout: image с feature OFF, один edge, малая cohort, затем расширение
  только после outbound-tag, latency и fallback evidence.
- Rollback: удалить `asyncDnsRoute` из process config или отключить canary;
  core immediately returns to default route without cache migration.

## Owner repo

`evasionlab/Xray-core`

## Downstream consumers

`evasionlab/XrayR`, `evasionlab/vpn.bot` runtime-config compiler/delivery,
`vpn.infra` edge roles, shared resolver/classifier infrastructure and VPN
clients using the resolver listener.

## Org-wide ADR

Да. Решение меняет cross-product dataplane, shared cache/storage и DNS
delivery-flow. Локальный implementation ADR должен быть дополнен org-wide
record в `evasionlab/infra` до production canary.

## 2026-09-08: Ограниченный stale-while-revalidate и фоновые повторы

Статус дополнения: Accepted; реализация и изолированные проверки, production
пока остаётся на прежней версии. Этот раздел заменяет вышеописанное требование
«только fresh RU» исключительно для opt-in `staleGraceMillis > 0`.

L1 разделяет freshness и окончательный срок хранения. После freshness последняя
классификация может использоваться до hard deadline, пока bounded worker
обновляет её в фоне. Успешный `other` немедленно заменяет прежний RU. Ошибка,
pending и повторное чтение не продлевают hard deadline; после него действует
обычный fallback. Это осознанный риск кратковременно устаревшего маршрута,
а не обещание постоянной доступности RU-egress.

- `staleGraceMillis` по умолчанию 0; начальное значение canary — 600000 (10 минут).
  Нет изменения DNS TTL через искусственное увеличение minTTL.
- POST `/v1/classify` сохраняется; новый edge передаёт `allowStale: true` только
  при включённом grace. `ready.ttlMillis` — оставшаяся свежесть;
  `staleTtlMillis` — оставшийся **полный** срок до hard expiry, не добавочный grace.
  `stale` допустим только opt-in потребителю и имеет ttlMillis=0. Legacy endpoint
  без allowStale не отдаёт устаревшую запись как fresh ready.
- `generation` меняется только после успешного canonical DNS fill. Повторный
  ready/stale того же поколения не возобновляет локальный stale grace. При этом
  доказанная оставшаяся freshness остаётся usable; новый DNS result может дать
  новый срок. Старый producer без generation трактуется консервативно.
- L1 вычитает время HTTP-запроса и ограничивает сроки серверными remaining TTL
  и локальными caps. Старый classifier без нового поля не даёт права на stale.
- Один bounded scheduler доводит pending/error до результата с конечным
  бюджетом попыток, а также обновляет недавно использованные записи заранее.
  Нет goroutine/timer на каждый домен, неограниченной retry-map или сетевого
  ожидания в Apply. Close отменяет фоновые запросы.
- Общий L2 использует отдельный versioned подпрефикс выделенного keyspace,
  зависящий от GeoIP и resolver view. Старые данные не мигрируют и не удаляются.
  В кеш не попадают outbound tags или ручные политики.

Порядок статических правил, AsIs и raw-IP/CDN приоритеты не меняются. Public
client DNS остаётся выключенным. Transport edge→classifier — существующий
public HTTPS с allowlist+bearer; management overlay не заменяет этот путь.

Минимальные доказательства: nonblocking cold miss, autonomous pending→ready,
expiry/error до и после hard deadline, RU→other, bounded flood/Close и общий
L2 на втором edge. Затем один Gauss, малая Gauss cohort; расширение только на
согласованную группу bypass после traffic evidence. Не весь edge fleet.
Rollback: убрать staleGraceMillis, при необходимости прежний immutable XrayR
image. Старый classifier остаётся доступен через существующий blue/green owner.
Cross-product дополнение — тот же infra ADR-20260904-02, без нового owner.

## 2026-09-28: Успешный обмен и свежесть L1 учитываются отдельно

В наблюдении wellserver6 классификатор отвечал HTTP 200, но часть `ready`
имела remaining TTL меньше времени запроса. Это нормальное окончание свежести,
а не transport/HTTP failure. Валидные `ready`, `stale`, `pending` и `ready`,
потерявший свежесть за время обмена, учитываются в `successes`; последний
получает отдельный `expiredResponses`, не увеличивая `errors`.

Expired ready не превращается в fresh. При opt-in stale он может заполнить L1
только до `min(requestStart + staleTtlMillis, requestStart + ttlMillis + grace)`.
Прежние hard deadlines/tombstones дополнительно ограничивают этот срок; ещё
свежая локальная запись не вытесняется. При выключенном stale или истёкшем hard
результат не устанавливается. Задача остаётся в том же bounded retry budget и
backoff, пока не получит fresh ready или не исчерпает лимит. Исходный ready с
нулевым TTL, противоречивые сроки и неверная схема ответа остаются ошибками.

Первое чтение или доказанная новая generation сохраняет prefetch на 80% свежести.
После повторного чтения той же (либо неизвестной legacy) generation следующий
запрос назначается на принятый абсолютный `freshUntil`. Повторное уменьшение
интервала до 80% остатка исключено; freshness, local maxTTL и hard bounds не
продлеваются. L2 продолжает обновляться своим существующим owner после expiry.

Минутная статистика разделяет `freshResponses`, `staleResponses`,
`pendingResponses`, `expiredResponses` и фиксированные причины настоящих ошибок:
`timeoutErrors`, `canceledErrors`, `transportErrors`, `httpErrors`,
`invalidResponses`, `requestErrors`. Домены, URL, generation и произвольный текст
ошибки не попадают в метрики. Семантика `errors` сужена до реальных неуспешных
обменов/невалидных ответов; сравнивать её напрямую со старым image нельзя.
`requests` включает in-flight и отменённые при Close попытки, поэтому равенство
`requests = successes + errors` не гарантируется во время работы/закрытия.

Валидация: expired ready со stale и без него, anchored grace, сохранение fresh
last-good и tombstones, malformed/HTTP/timeout, bounded pending retries,
same-generation near-expiry без каскада, новая generation RU→other и reload.
Delivery: закреплённый core → XrayR CI artifact → isolated QA → wellserver6.
Это дополнение не меняет L2 protocol, classifier image или fleet configuration.
