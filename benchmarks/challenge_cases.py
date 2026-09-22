"""Additional synthetic challenge cases written after the first regression pass.

This is a one-pass stress sample, not an independent human-labelled corpus. Keep
results separate. Once rules are tuned to it, it too becomes a regression set.
"""

CASES = [
    ("lowercase_unprompted_names", "Передай документы [[PERSON|анне кузнецовой]] и [[PERSON|сергею орлову]]."),
    ("initials", "Клиент [[PERSON|Смирнова М. А.]] ждёт звонка."),
    ("name_no_label", "Напишите [[PERSON|Александру Кузнецову]] по электронной почте."),
    ("passport_unlabeled", "[[PASSPORT|4510 987654]]"),
    ("passport_words_broken", "Мой паспорт: серия [[PASSPORT|45 10, номер 987654]]"),
    ("birth_all_words", "Дата рождения: [[BIRTH_DATE|пятого мая две тысячи первого года]]."),
    ("birth_short_year", "Дата рождения: [[BIRTH_DATE|05.06.91]]"),
    ("birth_reverse", "Родился [[BIRTH_DATE|1995/25/12]]."),
    ("citizen", "Я гражданин [[CITIZENSHIP|Казахстана]]."),
    ("citizenship_long", "Гражданство: [[CITIZENSHIP|Республика Беларусь]]."),
    ("address_prose", "Я живу в [[ADDRESS|Новосибирске, на Красном проспекте, дом 12]], доставка завтра."),
    ("address_one_city", "Мой город: [[ADDRESS|Самара]]"),
    ("phone_international", "Телефон: [[PHONE|+44 20 7946 0958]]"),
    ("card_fifteen", "Номер карты: [[CARD|3782 822463 10005]]"),
    ("email_quoted", "Email: «[[EMAIL|customer.test@example.org]]»."),
    ("public_private_sentences", "Поэт Александр Пушкин написал роман. Клиент [[PERSON|Иван Петров]] оставил заявку."),
    ("negative_author", "Автор письма — [[PERSON|Николай Павлов]]."),
    ("negative_product", "На странице адрес доставки пока не указан."),
    ("negative_store", "Адрес магазина: Москва, ул. Арбат, дом 5."),
    ("negative_word_roman", "Клиент [[PERSON|Роман Иванов]] ждёт звонка."),
    ("birth_place_followup", "Место рождения: [[BIRTH_PLACE|Воронеж]]. Сейчас проживаю в [[ADDRESS|Туле]]."),
    ("multiple_people", "ФИО: [[PERSON|Петров Иван Иванович]]; получатель [[PERSON|Соколова Анна Петровна]]"),
]
