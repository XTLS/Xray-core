# ADR-0005: Ограниченный hedge для private classifier pool

- Status: Proposed
- Date: 2026-10-07
- Repo-owner: `evasionlab/Xray-core`
- Downstream consumers: `evasionlab/XrayR`, `vpn.infra`, `dns-route-cache`
- Org-wide ADR required: Yes
- Org-wide ADR link: https://github.com/evasionlab/infra/blob/main/docs/adr/ADR-20261001-01-dns-cache-first-connection-and-l1-persistence.md (ROOT владеет Proposed bounded concurrency addition).
- Implementation: только source preparation; CI, pointer change и runtime не разрешены этим документом.

## Context

ADR-0004 сохраняет общий configured request timeout и полное время здорового
первого endpoint. Сейчас failover последовательный: never-failed silent member
может потратить весь deadline. Actual default pool имеет три native endpoints и
150 мс; generic accepted configuration содержит 2–6 endpoints. Fast REJECT тест
не проверяет silent loss. Реальное наблюдение Rontgen содержит route timeout;
оно сохранено отдельно и не превращается в accounting exception.

## Problem

Первый ранее здоровый endpoint должен выдерживать ответ80 мс, а его silent loss
должен позволять живому peer ответить в той же операции150 мс. Последовательный
cap50 мс на каждый healthy member отбрасывает здоровые80 мс ответы. Эти свойства
требуют ограниченного параллельного запроса; новые goroutines и отмена losers
меняют amplification и attempt accounting.

## Decision

Один job сохраняет parent context и свой configured `requestTimeoutMillis`.
Первый eligible rotating member начинает сразу и сохраняет весь deadline.
Если через50 мс ответ ещё не завершён, начинается следующий eligible member.
Timer использует существующий reserve50 мс; это не новый глобальный150 мс timeout.
Одновременно не более двух HTTP attempts/job; каждый endpoint используется
не более одного раза. Total attempts <= configured eligible members <=6;
для actual default3 максимум3. При retryable terminal error освободившийся slot
может использовать следующий member без нового полного timeout. Пока два
attempts активны, третий ждёт slot; ради slot живой запрос не отменяется.
Known-failed probe сохраняет существующий child budget и passive cooldown.
Fully cooling pool остаётся synthetic error без HTTP. Worker count, job/queue
admission, retries, routeWait, L1/SWR/TTL и итоговый static fallback не меняются.

Первый успешный transport response является единственным результатом job,
включая pending/stale/other; authoritative неретраибельный error также завершает
job. До hedge deadline такие ответы не вызывают fanout. Начавшийся конкурентный
request отменяется и полностью drained перед возвратом job. Auth, private pins,
view/namespace и body остаются прежними. Никаких Redis writes/replay добавлять
нельзя; speculative classifier request использует прежние lease/fill fences.

Winner cancellation имеет отдельную cause и counter `winnerCanceled`, terminal
nonretryable stop — `operationCanceled`; external caller cancellation остаётся
`canceledErrors`. Только фактические transport/timeout/HTTP failures влияют на
passive cooldown; own winner cancellation не доказывает unhealthy peer. Уже
полученная настоящая ошибка сохраняется даже если другой attempt выиграл.
Ни один attempt goroutine не остаётся после возврата coordinator; buffered result
channel на max2 и context-aware private HTTP transport обеспечивают drain.

Typed metrics разделяют started attempts, completed endpoint attempts, successes,
real errors, winner cancellations и terminal cancellations. `poolAttempts` остаётся
started, `poolFailovers` — starts после первого, `hedgeStarts` — starts при уже
активном запросе. Route requests/outcomes остаются job counters. Нельзя требовать
endpoint attempts == completed routes: успешный job может завершить winner и
canceled loser. Измерение должно сохранять все реальные endpoint failures и own
cancels; route errors должны оставаться0 для healthy business gate. В stable
terminal fixture endpoint terminal partition равен attempts; на production
snapshot inflight transport и inflight job учитываются раздельно, без произвольной
числовой tolerance. Два overlapping attempts могут оба завершить decode до отмены:
оба реальные successes сохраняются, но job возвращает один выбранный response.
`attempts - winnerCanceled == route completions` тоже не является инвариантом:
есть surplus successes. `elapsedGT150` относится ко всем attempts, включая
cancel/drain loser, и само по себе не доказывает timeout. Новый reader сохраняет
histogram целиком, но отличает реальные failures от own cancellation и проверяет
business route outcome отдельно. На точной границе deadline/result-ready Go select
может выбрать готовый valid result либо истёкший context; decoded endpoint success
не переписывается в timeout/cancel из-за итогового deadline outcome job.
Обновление reader/verifier требует отдельного full source review.

## Alternatives

- Последовательный full budget сохраняет80 мс, но silent first может сорвать job.
- Cap50 мс всем healthy members нарушает80 мс contract.
- Fanout всем3/6 повышает amplification; максимум2 выбран вместо него.
- Увеличение configured timeout или routeWait маскирует проблему и отклонено.
- Новые фоновые probes и proxy добавляют lifecycle и не нужны.

## Consequences

При здоровом first<50 мс выполняется ровно1 request. При first80 мс выполняется
ровно2: исходный first выигрывает, loser отменён без health penalty. Поэтому
literal calls1 в прежнем80 мс fixture меняется намеренно; response identity,
80 мс success и прежний общий deadline сохраняются. Silent first + secondary80 мс
завершается около130 мс в actual150 мс budget. Это проверка controlled fixture,
а не обещание сети/OS scheduling или доказательство physical host loss.
Generic six-fast503 fixture сохраняет шесть последовательных attempts; pool
validation и sorted namespace identity не меняются. Общий pressure может вырасти
до двух active requests на существующий worker, без роста workers/queue caps.
Backend limits HTTP500qps/burst100/maxInflight8/demand64 сохраняются; source fix
не повышает их. Перед ALL-consumer HA claim aggregate demand при потере одного
backend должен помещаться в observed surviving capacity. Rontgen timeout сам по
себе не устанавливает capacity cause и не разрешает новую программу настройки.

Перед release нужны реальные isolated HTTP fixtures: original80 winner identity,
fast<50 single, каждый selected-first silent member, retryable error visibility,
all-fail bound, parent cancel, max2 active, unique attempts, repeated drain/socket
cleanup. Затем exact CI binary и canary business/process ACK + silent endpoint
loss с bounded restoration; runtime fleet пока HOLD. Rollback возвращает прежний
immutable XrayR artifact и private operator preimage через действующий writer;
L2/token/namespace не удаляются. Org-wide draft фиксирует тот же concurrency и
measurement contract, без нового delivery workflow или feature flag.

### Passive cooldown и сохранение доступности

Canary silent-loss выявил отдельный дефект selection: после единичных timeout
оба surviving endpoints попали в cooldown; job без eligible кандидатов возвращал
synthetic transport error без сетевой попытки. Единственный eligible endpoint
также остаётся без hedge по source, даже когда cooled backup уже мог ответить.
Это воспроизводимый source-риск; причина одного production timeout не доказана.

Cooldown остаётся предпочтением, а не запретом резервной попытки. При минимум
двух eligible endpoints прежний round-robin не меняется. При нуле или одном
eligible selection дополняет список только до двух уникальных кандидатов:
сначала меньше passive failures, затем ближайшее cooldown expiry; при равенстве
сохраняется текущий round-robin порядок. Такие кандидаты `knownFailed=true`.
Это предпочитает surviving endpoint с одним timeout dead primary с шестью,
но не объявляет cooled endpoint здоровым. Истечение cooldown по-прежнему
возвращает primary в обычный список; реальный успех очищает passive failure state.

`cooldownSkips` считает только фактически исключённые cooled members; выбранный
резерв сохраняет обычные attempt/timeout/success/cancel counters. Новых полей
telemetry нет. При fast healthy <50 мс резерв не запускается. Общий configured
job deadline, максимум две одновременные попытки, уникальные endpoints, workers,
queue, auth/terminal responses и namespace не меняются. При полном отказе
сохраняются реальные bounded attempts и errors вместо ложной synthetic cooldown
недоступности. Давление на восстановившийся backend может возрасти в пределах
уже принятого max2; лимиты backend не повышаются. Это SOURCE-коррекция внутри
контракта; прежнее реальное fault failure остаётся evidence, runtime HOLD.
