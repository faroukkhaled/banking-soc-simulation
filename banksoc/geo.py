import math

COORDS = {
    "QA": (25.29, 51.53), "AE": (25.20, 55.27), "EG": (30.04, 31.24), "GB": (51.51, -0.13),
    "DE": (52.52, 13.40), "US": (38.90, -77.04), "RU": (55.75, 37.62), "NG": (9.08, 7.40), "CN": (39.90, 116.40),
}


def haversine_km(a, b):
    (la1, lo1), (la2, lo2) = COORDS[a], COORDS[b]
    p1, p2 = math.radians(la1), math.radians(la2)
    dp, dl = p2 - p1, math.radians(lo2 - lo1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))
