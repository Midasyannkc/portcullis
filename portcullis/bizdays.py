from datetime import date, timedelta

HOLIDAYS = {date(2026, 11, 26), date(2026, 12, 25), date(2027, 1, 1)}


def add_business_days(d: date, n: int, holidays=HOLIDAYS) -> date:
    step = 1 if n >= 0 else -1
    left = abs(n)
    while left:
        d += timedelta(days=step)
        if d.weekday() < 5 and d not in holidays:
            left -= 1
    return d


def business_days_between(a: date, b: date, holidays=HOLIDAYS) -> int:
    if b < a:
        return -business_days_between(b, a, holidays)
    n, d = 0, a
    while d < b:
        d += timedelta(days=1)
        if d.weekday() < 5 and d not in holidays:
            n += 1
    return n
