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

## Альтернативы

- Глобальный `IPOnDemand`: отклонён, так как блокирует route selection DNS.
- Local-only cache на каждом edge: отклонён, так как дублирует cold resolve и
  classification по fleet.
- Remote Redis/gRPC lookup из `PickRoute`: отклонён, так как вводит сеть в
  критический путь соединения.
- Runtime policy update на каждый DNS ответ: отклонён, так как создаёт storm в
  owner delivery и не имеет TTL/lifecycle semantics.

## Последствия

- Нужны HA L2 classifier-cache и два resolver endpoints, доступные edge по
  private overlay; их outage не влияет на established known-good routing.
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
