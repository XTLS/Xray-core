# ADR-0005: Ограниченный hedge для private classifier pool

- Status: Accepted
- Date: 2026-10-07
- Repo-owner: `evasionlab/Xray-core`
- Downstream consumers: `evasionlab/XrayR`, `vpn.infra`, `dns-route-cache`
- Org-wide ADR required: Yes
- Org-wide ADR link: https://github.com/evasionlab/infra/blob/main/docs/adr/ADR-20261001-01-dns-cache-first-connection-and-l1-persistence.md
- Org-wide addition status: Accepted; минимальное уточнение max6 в существующем дополнении ведёт org-owner.
- Implementation status: max6 — принятое SOURCE-уточнение в рамках поручения пользователя о HA, проверяемое focused race tests. Обычная source delivery разрешена поручением пользователя; runtime canary pending. Прежняя max3 реализация и её evidence сохраняются.

## Контекст и проблема

ADR-0004 сохраняет configured request timeout и полное время здорового первого
endpoint. Actual default pool содержит три native endpoints и бюджет150 мс;
принятая generic configuration содержит2–6 endpoints. Sequential failover
позволяет silent first потратить весь deadline. Ограниченный max2 hedge устранил
этот случай для одного живого backup, но не гарантирует доступность неизвестного
третьего: self headers stall + expired failed central могут занять оба slots,
оставив живой cooled third без попытки. Это воспроизводимый независимый риск.

Retained production fault954/1 остаётся FAIL; его единственная timeout причина
не установлена по aggregate counters. Предыдущие cooldown synthetic errors
также сохранены: cooldown нельзя считать запретом на резервную попытку.
FIRST historical-health fixture показал, что child reserve50 отменяет sole
recovered80 primary примерно на51 мс; два остальных silent members завершают
job по parent150. Это отдельный воспроизведённый дефект, не доказательство причины954.

## Принятое решение

Job сохраняет parent context и configured `requestTimeoutMillis`; новый deadline
не вводится. Primary rotating eligible member запускается сразу. Если он ещё
не завершён через существующие50 мс, один hedge заполняет свободные slots:
active <= min(6,N), каждый endpoint используется не более одного раза,
unique total attempts <= configured N <=6. Освободившийся slot после retryable
error может занять следующий member. Живой request не отменяется ради slot.
Fast first<50 мс остаётся единственной попыткой; original80 response при двух
alternates80 сохраняется победителем. Более быстрый backup может выиграть раньше.

Passive cooldown остаётся предпочтением: eligible members идут в round-robin
порядке, затем все cooled members (меньше failures, ближайшее expiry, текущий
round-robin tie order). Ни один из configured2–6 members не исключён. Поэтому
`cooldownSkips` равен нулю для корректного fixed pool; это не означает сетевую
попытку на каждом job — fast first завершает job до hedge. Background probes/
half-open state не добавляются. Реальный успех очищает failure state; собственная отмена
winner не штрафует здоровье.

Для всех разрешённых N=2–6 каждый member имеет slot и использует прежний полный
parent context, включая historical failure/cooldown. Условный knownFailed child
reserve50/remaining/2 удалён: ожидание будущего slot больше не нужно и не должно
убивать sole recovered80. N>6 по-прежнему отвергается parser, не обрезается.
Generic six-fast503 fixture остаётся six unique attempts. Default3 scheduling/
50ms hedge/full parent остаются прежними; namespace/membership не меняются.

Первый valid response — единственный результат job, включая pending/stale/other;
authoritative nonretryable auth/terminal error завершает job без retry. Конкуренты
отменяются и drained до возврата coordinator; buffered channel соответствует
max6 (фактический размер N). Parent/external cancellation сохраняется. Workers, job/queue admission,
routeWait, L1/SWR/TTL, final static fallback, private auth/view/namespace и payload
не меняются; Redis writes/replay или новые probes не добавляются.

## Наблюдаемость и проверка

Winner cancellation — `winnerCanceled`, terminal stop — `operationCanceled`,
external cancellation — прежний caller cancellation. Только реальные
transport/timeout/HTTP failures влияют на passive cooldown. Реальная ошибка
сохраняется даже когда другой attempt выиграл. Диагностический MaxConcurrent
принимает6; остальные typed42/52 schemas неизменны.

Started attempts и route jobs имеют разные счётчики. Несколько responses могут
завершить decode до отмены: все настоящие endpoint successes сохраняются,
возвращается один original winner. Поэтому ни endpoint completions==routes, ни
attempts-minus-winnerCanceled==routes не являются инвариантами. Inflight jobs
и attempts проверяются раздельно; произвольная tolerance не вводится. Полная
terminal partition и histogram сохраняются. `elapsedGT150` включает canceled
losers и сам по себе не доказывает реальный timeout; реальные поздние outcomes
и собственные cancels различаются. На границе deadline/result-ready select
может выбрать valid result либо expired context; endpoint success не переписывается.

Focused synthetic/race proof покрывает fast single, original80 winner, каждого
sole healthy80 с двумя silent members, шесть historical-health permutations,
configured2 recovered80, generic4 full parent, generic6 fast503,
реальные errors/auth, parent cancellation, all-fail deadline и drain/socket cleanup.
Concurrent surplus-success fixture сохраняет три настоящих successes и один
возвращённый original response. Это controlled source evidence, не production HA.
Нужны exact CI binary, действующий writer, physical process Hello/ACK, natural
business proof и bounded silent-loss canary с автоматическим restoration.

## Альтернативы

- Sequential full budget не оставляет времени после silent first.
- Healthy child cap50 нарушает успешный80 мс contract.
- Max2 с health ranking не покрывает неизвестные два silent members и third80
  в150 мс; half-open80 может постоянно отменяться быстрым backup20@50.
- Fanout сразу всем3/6 увеличивает обычную нагрузку; выбран прежний delayed hedge50.
- Max3 плюс child reserve не покрывает sole recovered80 в каждом из шести slots
  среди пяти silent peers: история здоровья не является oracle фактической доступности.
- Parent/routeWait increase маскирует отказ и не принят.
- Background probes и новые foreground limiters не входят в это решение.

## Последствия, capacity и границы

Новый isolated fixture покрывает sole healthy80 в каждой из шести позиций среди
пяти silent peers: unknown history, expired known failure и все members cooled.
У каждой попытки точный общий configured parent deadline; unique/active<=6,
терминальные counters и cancel/drain сохраняются. All-silent и caller-cancel
проверяют cause, отсутствие оставшихся transport calls, диагностический cap6/4KiB.
Это synthetic source proof, не объяснение retained954/1 и не runtime acceptance.

При controlled sole healthy80 backup начинает на50 мс и отвечает около130 мс;
OS/network tail не гарантируется. Max3 повышает amplification: retained single
caller740 jobs/776 attempts/36 own cancels за60.025 с дают conditional812 attempts
при тех же36 slow events (+4.64%). All-slow worst3 requests/job вместо2 (+50%).
Это историческая проекция max3 одного caller, не измерение fleet capacity.
Для нового N6 worst all-slow6 requests/job вместо3 (+100%); fast first<50
по-прежнему1. При J jobs и H slow hedge jobs: до J+5H вместо J+2H, добавка3H.
При W реально активных jobs максимум6W attempts, queue не запускает HTTP сама.
Retained740/776/36 не измеряют распределение N6 и не позволяют вычислить его
реальную offered load/capacity.

HTTP500QPS/burst100/inflight8 относятся только к `/v1/warm`. Foreground
`/v1/classify` явного HTTP QPS/inflight admission cap не имеет. Backend
backgroundfill64workers/256queue не ограничивает foreground HTTP. Redis component
50 мс/GetEntry100 мс и actual connection-pool capacity нельзя вывести из warm
limits; actual production pool capacity здесь не подтверждена. Hedge50 + backend100
оставляют нулевой reserve на прочую обработку; remaining-budget contract отдельно.

Core job bounds — configured workers(default2,max64), queue(default256,max100000),
cache/jobs(default4096,max100000). Cloned DefaultTransport MaxConnsPerHost0:
idle bounds не ограничивают active requests. Изолированный fixed-offer32 fixture
использует Workers2/queue4/jobs8 и Redis semaphore1/2 с acquire50/lookup100;
наблюдает max6 HTTP и pool refusal, затем stop/cancel/drain. Это конечная synthetic
модель, не actual Redis configuration и не production capacity acceptance.
Лимиты backend не повышаются; перед ALL-consumer HA claim surviving capacity
и реальный traffic outcome требуют самостоятельного evidence.

Owner Core хранит scheduling/accounting; XrayR интегрирует точную зависимость через
действующий scoped writer, infra/node writer сохраняет ownership.
Rollback возвращает прежний immutable XrayR artifact и точный private preimage;
L2/token/namespace не удаляются. Новых workflows/flags/ADR по названию bugfix нет.
Accepted означает source-решение, не Rolled; max6 runtime canary pending: retained954/1 и исходные failed
fixtures не переинтерпретируются позднейшим успешным window.
