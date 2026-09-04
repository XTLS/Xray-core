# ADR-0002: Явная совместимость с legacy raw VLESS egress

- Status: Canary
- Date: 2026-09-04
- Repo-owner: `evasionlab/Xray-core`
- Downstream consumers: `evasionlab/XrayR`, `evasionlab/vpn.infra` edge role, legacy VLESS egress
- Org-wide ADR required: Yes; linked record: `evasionlab/infra/docs/adr/ADR-20260904-02-async-shared-dns-route-cache.md`

## Контекст

Актуальный upstream Xray-core запрещает VLESS без transport TLS или другого
encryption при публичном IP назначения. В production есть существующий
trusted-egress transport VLESS/TCP/none; его сервер не обслуживает TLS, поэтому
механическое включение TLS сломает соединение.

## Проблема

Без явной compatibility policy обновление Xray-core не стартует XrayR до
получения runtime config и переводит edge в restart loop. Глобальное снятие
upstream-проверки расширило бы этот риск для всех новых outbound'ов.

## Решение

Добавить opt-in поле outbound `allowInsecureVlessOutbound`. По умолчанию
upstream-проверка public raw VLESS сохраняется. Поле действует только для
VLESS и только на конкретный outbound; Trojan и все непомеченные VLESS
outbound'ы по-прежнему требуют transport security.

`vpn.infra` помечает только уже работающие legacy raw-VLESS egress entries.
Перевод такого egress на TLS/Reality остаётся отдельной миграцией.

## Альтернативы

- Включить TLS на существующем egress: отклонено, поскольку peer его не
  обслуживает и это немедленно ломает транспорт.
- Удалить upstream validation глобально: отклонено, поскольку позволяет
  случайно добавить любой public raw VLESS transport.
- Оставить старую версию core: отклонено, поскольку блокирует async DNS route
  feature и актуальные upstream fixes.

## Последствия

- Обновление core остаётся возможным только для явно сохранённых legacy
  transport'ов.
- Новые raw VLESS outbound'ы требуют видимого config opt-in и code review.
- Rollback: удалить поле или вернуть предыдущий immutable XrayR image; default
  validation вернётся без изменения runtime route policy.
