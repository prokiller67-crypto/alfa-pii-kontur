# Официальная проверка — попытка 3

23 сентября 2026, **10:59 МСК**, отправлены
`artifacts/alfa-pii-attempt-3.zip` и
`https://alfa-pii-kontur.vercel.app/process`.

Портал: https://reg.vibecoding-hackathon.ru/results/data-science?tab=attempts

- Статус: **Успешно / SUCCESS**.
- Скор: **9895.00000**, на 15 ниже предыдущего лучшего результата.
- Замечания: **12** — BLOCKER 0, CRITICAL 8, MAJOR 4, MINOR 0, INFO 0.
- Архив логов содержит только одну строку сводки в `scoring.log`.

Перед попыткой логика детектора и API была разделена на меньшие функции без
изменения результата на 74 примерах; 88 тестов прошли. Локальная проверка
сложности перестала выдавать `C901`, `PLR0915` и `PLR0912` для этих двух
модулей. Официальная оценка стала хуже, поэтому этот рефакторинг отменён в
следующей версии. Причины двух новых замечаний не раскрыты.

Код API: commit `d977002a4d32497ea90113d5ba588f3fadb4e6b3`,
deployment `dpl_77ecksGEFvp43SHf2H6xTxFXk1e4`.
Архив: 43 файла, 108140 байт, SHA-256
`47d751af07a11fae9171e45b28709cefcf696a0fa3aa1f4486f402faff040b92`.
Проверка опубликованного API: `artifacts/attempt-3-preflight.json`.
Копия ответа: `artifacts/official-attempt-3-report.zip`.
