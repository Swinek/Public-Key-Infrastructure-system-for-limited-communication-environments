"""Generator diagramu przypadków użycia (UML 2) -> przypadki_uzycia.svg.

Uruchomienie: python3 praca/diagramy/przypadki_uzycia.py
Węzły i relacje są zdefiniowane niżej; punkty styku linii z elipsami liczone są automatycznie.
"""
import math
from pathlib import Path
from xml.sax.saxutils import escape

W, H = 1740, 1190
FONT = "Helvetica, Arial, sans-serif"
INK = "#1f2328"

# --- przypadki użycia: id -> (x, y, tekst, rx) ---------------------------------------------------
UC = {
    # Centrum PKI
    "R0": (300, 140, "Zainicjuj Root CA\n(ECDSA P-256)", 95),
    "R1": (365, 206, "Rozpatrz\nwniosek CSR", 100),
    "R2": (405, 272, "Odwołaj certyfikat", 100),
    "R3": (405, 338, "Wystaw CRL\nna żądanie", 100),
    "R4": (365, 404, "Przeglądaj stan PKI\n(CA, CRL, rejestr)", 100),
    "R5": (300, 470, "Eksportuj CRL\nna nośnik (DER)", 95),
    "C1": (690, 130, "Odrzuć\nwniosek CSR", 100),
    "C2": (690, 218, "Zatwierdź\nwniosek CSR", 100),
    "C3": (960, 140, "Potwierdź odcisk klucza\n(kanał pozasystemowy)", 112),
    "C4": (960, 240, "Wydaj certyfikat X.509\n(podpis kluczem CA)", 112),
    "C5": (960, 345, "Wystaw i podpisz CRL\n(CRLNumber + 1)", 112),
    "C6": (1205, 440, "Powiadom węzły online\n(impuls przez WAN)", 115),
    "C7": (1410, 345, "Odśwież CRL\nokresowo (co 24 h)", 105),
    # Edge client
    "E0": (300, 604, "Przeglądaj pomiary\ntransferu (WAN / P2P)", 100),
    "E1": (360, 670, "Sprawdź certyfikat\noffline", 100),
    "E2": (395, 736, "Uzyskaj certyfikat węzła\n(klucz w węźle + CSR)", 100),
    "E3": (360, 802, "Wyślij wiadomość\nlub plik", 100),
    "E4": (300, 868, "Wczytaj CRL\nz nośnika", 100),
    "E5": (680, 768, "Przenieś dane metodą\nstore-and-forward", 100),
    "E6": (590, 940, "Zweryfikuj obiekt PKI\n(podpis CA, pin, CRLNumber)", 112),
    "E7": (805, 885, "Rozgłoś nowe dane\nsąsiadom (announce)", 95),
    "E8": (805, 1010, "Synchronizuj dane PKI\nprzy kontakcie", 95),
    # Edge app
    "V":  (1182, 780, "Zweryfikuj certyfikat\noffline (łańcuch,\nważność, CRL)", 105),
    "A1": (1425, 620, "Pobierz certyfikat\ni dane PKI", 105),
    "A2": (1425, 720, "Wyślij wiadomość\nszyfrowaną (ECIES)", 105),
    "A3": (1425, 820, "Odczytaj wiadomość\nszyfrowaną", 105),
    "A4": (1425, 940, "Uwierzytelnij węzły\n(challenge–response)", 105),
}
RY = {"V": 33}
DEFAULT_RY = 26

# --- aktorzy: id -> (x, y, nazwa, rodzaj) --------------------------------------------------------
ACTORS = {
    "admin": (75, 305, "Administrator CA", "human"),
    "sched": (1640, 345, "Harmonogram\nCRL", "system"),
    "oper":  (75, 735, "Operator węzła", "human"),
    "neigh": (985, 880, "Sąsiedni\nEdge client", "system"),
    "link":  (985, 1032, "Łączność\n(client.sh)", "system"),
    "user":  (1655, 740, "Użytkownik\nEdge app", "human"),
    "peer":  (1655, 1000, "Zdalna\nEdge app", "system"),
}

# --- relacje: (rodzaj, od, do, etykieta, t, przesunięcie) -----------------------------------------
# assoc: aktor -- przypadek; include/extend: od -> do (strzałka przy "do"); gen: dziecko -> rodzic
REL = [
    *[("assoc", "admin", u) for u in ("R0", "R1", "R2", "R3", "R4", "R5")],
    ("gen", "C1", "R1"), ("gen", "C2", "R1"),
    ("include", "C2", "C3"), ("include", "C2", "C4"),
    ("extend", "R2", "C2", "«extend»\n{węzeł ma już certyfikat}", 0.5, 14),
    ("include", "R2", "C5", None, 0.42, -9),
    ("include", "R3", "C5", None, 0.42, 11),
    ("include", "C7", "C5"),
    ("include", "C5", "C6"),
    ("assoc", "sched", "C7"),

    *[("assoc", "oper", u) for u in ("E0", "E1", "E2", "E3", "E4")],
    ("include", "E1", "V", None, 0.82, -10),
    ("extend", "E5", "E2", "«extend»\n{brak łącza WAN}", 0.5, -16),
    ("extend", "E5", "E3", "«extend»\n{adresat poza zasięgiem}", 0.5, 18),
    ("include", "E5", "E6", None, 0.5, 34),
    ("include", "E4", "E6", None, 0.5, 12),
    ("include", "E8", "E6", None, 0.5, 12),
    ("extend", "E7", "E8", "«extend»\n{nowsza wersja}", 0.5, 52),
    ("assoc", "neigh", "E5"), ("assoc", "neigh", "E8"), ("assoc", "link", "E8"),

    *[("assoc", "user", u) for u in ("A1", "A2", "A3", "A4")],
    ("assoc", "peer", "A4"),
    ("include", "A2", "V", None, 0.5, -10),
    ("include", "A3", "V", None, 0.55, -10),
    ("include", "A4", "V", None, 0.5, 12),
]

SUBJECTS = [
    (170, 58, 1560, 506, "Centrum PKI – urząd certyfikacji, panel administratora, portal WAN", "#f3f6fb"),
    (170, 532, 905, 1066, "Edge client – węzeł brzegowy (dystrybucja PKI)", "#f3f8f2"),
    (1060, 532, 1560, 1066, "Edge app – użytkownik certyfikatu", "#fbf6ef"),
]

NOTES = [
    # (x, y, w, tekst, kotwica: (x, y) albo None)
    (1095, 118, 440, "Klucz prywatny Root CA istnieje wyłącznie w Centrum.\n"
                    "Edge client i Edge app niczego nie podpisują kluczem CA –\n"
                    "tylko weryfikują podpisy.", None),
    (1095, 196, 440, "Portal (:5001, konto bazy tylko do odczytu) publikuje CA,\n"
                     "CRL i certyfikaty oraz przyjmuje CSR – jedyny styk\n"
                     "z węzłami przez łącze WAN.", None),
    (1350, 410, 185, "Wyzwalane też decyzją\n"
                     "w sprawie CSR (NOTIFY\n"
                     "crl_issued / cert_issued).", ("C6", 1320, 440)),
    (205, 968, 255, "Kontakt = internet on, hello / hello-ack\n"
                    "lub announce. Brak timerów: najpierw\n"
                    "/pki/summary, potem pull tylko\n"
                    "brakujących obiektów.", ("E8", 711, 1006)),
    (1072, 925, 228, "verify(cert, CA, CRL, now) →\n"
                     "valid | revoked | invalid | unknown\n"
                     "(wspólny weryfikator\n"
                     "edge_app/pki)", ("V", 1182, 813)),
]

# -------------------------------------------------------------------------------------------------
out = []
add = out.append


def text(x, y, s, size=13, anchor="middle", weight="normal", style="normal", halo=False, lh=None):
    lines = s.split("\n")
    lh = lh or size + 2
    y0 = y - (len(lines) - 1) * lh / 2 + size * 0.35
    extra = ' paint-order="stroke" stroke="#ffffff" stroke-width="5" stroke-linejoin="round"' if halo else ""
    spans = "".join(
        f'<tspan x="{x:.1f}" y="{y0 + i * lh:.1f}">{escape(l)}</tspan>' for i, l in enumerate(lines))
    add(f'<text font-size="{size}" text-anchor="{anchor}" font-weight="{weight}" '
        f'font-style="{style}"{extra}>{spans}</text>')


def uc_geom(k):
    x, y, _, rx = UC[k]
    return x, y, rx, RY.get(k, DEFAULT_RY)


def actor_box(k):
    x, y, _, kind = ACTORS[k]
    return (x, y - 8, 26, 42) if kind == "human" else (x, y, 70, 29)


def boundary(k, tx, ty):
    """Punkt na brzegu elementu k w kierunku (tx, ty)."""
    if k in UC:
        cx, cy, rx, ry = uc_geom(k)
        dx, dy = tx - cx, ty - cy
        t = 1 / math.sqrt((dx / rx) ** 2 + (dy / ry) ** 2)
        return cx + dx * t, cy + dy * t
    cx, cy, hw, hh = actor_box(k)
    dx, dy = tx - cx, ty - cy
    t = min(hw / abs(dx) if dx else 1e9, hh / abs(dy) if dy else 1e9)
    return cx + dx * t, cy + dy * t


def center(k):
    return UC[k][:2] if k in UC else actor_box(k)[:2]


add(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
    f'font-family="{FONT}" fill="{INK}">')
add('<title>Diagram przypadków użycia – PKI w warunkach ograniczonej łączności</title>')
add(f'''<defs>
<marker id="open" viewBox="0 0 12 12" refX="11" refY="6" markerWidth="12" markerHeight="12" orient="auto" markerUnits="userSpaceOnUse">
  <path d="M1,1 L11,6 L1,11" fill="none" stroke="{INK}" stroke-width="1.3"/></marker>
<marker id="tri" viewBox="0 0 16 16" refX="15" refY="8" markerWidth="16" markerHeight="16" orient="auto" markerUnits="userSpaceOnUse">
  <path d="M1,1 L15,8 L1,15 Z" fill="#ffffff" stroke="{INK}" stroke-width="1.3"/></marker>
</defs>''')
add(f'<rect width="{W}" height="{H}" fill="#ffffff"/>')

# ramka diagramu UML 2 (uc)
add(f'<rect x="12" y="12" width="{W - 24}" height="{H - 24}" fill="none" stroke="{INK}" stroke-width="1.4"/>')
tag = "uc  System generowania i dystrybucji certyfikatów w sieci o ograniczonej łączności"
tw = len(tag) * 7.4 + 24
add(f'<path d="M12,12 H{12 + tw:.0f} V30 L{tw - 2:.0f},42 H12 Z" fill="#ffffff" stroke="{INK}" stroke-width="1.4"/>')
text(22, 27, tag, size=14, anchor="start", weight="bold")

# podmioty (system boundary)
for x1, y1, x2, y2, title, fill in SUBJECTS:
    add(f'<rect x="{x1}" y="{y1}" width="{x2 - x1}" height="{y2 - y1}" fill="{fill}" stroke="{INK}" stroke-width="1.3"/>')
    text((x1 + x2) / 2, y1 + 13, "«subsystem»", size=11, style="italic")
    text((x1 + x2) / 2, y1 + 29, title, size=14, weight="bold")

# notatki
for nx, ny, nw, s, anchor in NOTES:
    lines = s.count("\n") + 1
    nh = lines * 15 + 12
    if anchor:
        _, ax, ay = anchor
        px = nx + nw / 2 if nx <= ax <= nx + nw else (nx if ax < nx else nx + nw)
        py = ny + nh / 2 if ny <= ay <= ny + nh else (ny if ay < ny else ny + nh)
        add(f'<line x1="{px:.1f}" y1="{py:.1f}" x2="{ax}" y2="{ay}" stroke="{INK}" stroke-width="1" stroke-dasharray="3 3"/>')
    f = 10
    add(f'<path d="M{nx},{ny} H{nx + nw - f} L{nx + nw},{ny + f} V{ny + nh} H{nx} Z" fill="#fffef6" stroke="{INK}" stroke-width="1"/>')
    add(f'<path d="M{nx + nw - f},{ny} V{ny + f} H{nx + nw}" fill="none" stroke="{INK}" stroke-width="1"/>')
    text(nx + 9, ny + nh / 2, s, size=11.5, anchor="start", lh=15)

# relacje (pod elipsami)
labels = []
for r in REL:
    kind, a, b = r[:3]
    label = r[3] if len(r) > 3 else None
    t = r[4] if len(r) > 4 else 0.5
    off = r[5] if len(r) > 5 else -10
    (ax, ay), (bx, by) = center(a), center(b)
    x1, y1 = boundary(a, bx, by)
    x2, y2 = boundary(b, ax, ay)
    if kind == "assoc":
        add(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{INK}" stroke-width="1.2"/>')
        continue
    if kind == "gen":
        add(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{INK}" stroke-width="1.2" marker-end="url(#tri)"/>')
        continue
    add(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{INK}" stroke-width="1.1" '
        f'stroke-dasharray="6 4" marker-end="url(#open)"/>')
    label = label or f"«{kind}»"
    mx, my = x1 + (x2 - x1) * t, y1 + (y2 - y1) * t
    L = math.hypot(x2 - x1, y2 - y1) or 1
    nx_, ny_ = -(y2 - y1) / L, (x2 - x1) / L
    if ny_ > 0 or (ny_ == 0 and nx_ > 0):  # normalna "w górę" dla dodatniego przesunięcia ujemnego
        nx_, ny_ = -nx_, -ny_
    labels.append((mx - nx_ * off, my - ny_ * off, label))

# przypadki użycia
for k, (x, y, s, rx) in UC.items():
    ry = RY.get(k, DEFAULT_RY)
    add(f'<ellipse cx="{x}" cy="{y}" rx="{rx}" ry="{ry}" fill="#ffffff" stroke="{INK}" stroke-width="1.3"/>')
    text(x, y, s, size=12.5, lh=14.5)

for lx, ly, s in labels:
    text(lx, ly, s, size=11, style="italic", halo=True, lh=13)

# aktorzy
for k, (x, y, name, kind) in ACTORS.items():
    if kind == "human":
        g = f'stroke="{INK}" stroke-width="1.5" fill="none"'
        add(f'<circle cx="{x}" cy="{y - 38}" r="10" fill="#ffffff" stroke="{INK}" stroke-width="1.5"/>')
        add(f'<path d="M{x},{y - 28} V{y + 4} M{x - 18},{y - 16} H{x + 18} M{x},{y + 4} L{x - 14},{y + 28} '
            f'M{x},{y + 4} L{x + 14},{y + 28}" {g}/>')
        text(x, y + 48, name, size=13, weight="bold", lh=15)
    else:
        add(f'<rect x="{x - 70}" y="{y - 29}" width="140" height="58" fill="#ffffff" stroke="{INK}" stroke-width="1.3"/>')
        text(x, y - 14, "«system»", size=10.5, style="italic")
        text(x, y + 7, name, size=12.5, weight="bold", lh=14)
        # piktogram aktora w rogu
        ix, iy = x + 56, y - 20
        add(f'<g stroke="{INK}" stroke-width="1" fill="none"><circle cx="{ix}" cy="{iy}" r="3"/>'
            f'<path d="M{ix},{iy + 3} V{iy + 11} M{ix - 5},{iy + 6} H{ix + 5} M{ix},{iy + 11} L{ix - 4},{iy + 16} '
            f'M{ix},{iy + 11} L{ix + 4},{iy + 16}"/></g>')

# legenda
lx, ly = 1060, 1084
add(f'<rect x="{lx}" y="{ly}" width="520" height="88" fill="#ffffff" stroke="{INK}" stroke-width="1"/>')
text(lx + 12, ly + 15, "Legenda", size=12, anchor="start", weight="bold")
items = [
    ("assoc", "asocjacja aktor – przypadek użycia"),
    ("include", "«include» – zawsze wykonywany"),
    ("extend", "«extend» {warunek} – opcjonalny"),
    ("gen", "generalizacja (specjalizacja przypadku)"),
]
for i, (kind, s) in enumerate(items):
    cx = lx + 14 + (i % 2) * 245
    cy = ly + 40 + (i // 2) * 28
    attrs = {"assoc": "", "include": ' stroke-dasharray="6 4" marker-end="url(#open)"',
             "extend": ' stroke-dasharray="6 4" marker-end="url(#open)"', "gen": ' marker-end="url(#tri)"'}[kind]
    add(f'<line x1="{cx}" y1="{cy}" x2="{cx + 48}" y2="{cy}" stroke="{INK}" stroke-width="1.2"{attrs}/>')
    text(cx + 58, cy, s, size=11.5, anchor="start")

add("</svg>")

# kontrola układu: linia relacji nie może przecinać innych elips ani aktorów
for r in REL:
    a, b = r[1], r[2]
    (ax, ay), (bx, by) = center(a), center(b)
    for k in UC:
        if k in (a, b):
            continue
        cx, cy, rx, ry = uc_geom(k)
        if any(((ax + (bx - ax) * i / 200 - cx) / (rx + 4)) ** 2 + ((ay + (by - ay) * i / 200 - cy) / (ry + 4)) ** 2 < 1
               for i in range(201)):
            print(f"UWAGA: relacja {a}->{b} przecina {k}")
    for k in ACTORS:
        if k in (a, b):
            continue
        cx, cy, hw, hh = actor_box(k)
        if any(abs(ax + (bx - ax) * i / 200 - cx) < hw and abs(ay + (by - ay) * i / 200 - cy) < hh for i in range(201)):
            print(f"UWAGA: relacja {a}->{b} przecina aktora {k}")
for k1 in UC:
    for k2 in UC:
        if k1 < k2:
            x1, y1, rx1, ry1 = uc_geom(k1)
            x2, y2, rx2, ry2 = uc_geom(k2)
            if abs(x1 - x2) < rx1 + rx2 and abs(y1 - y2) < ry1 + ry2 + 8:
                print(f"UWAGA: {k1} i {k2} za blisko")
dst = Path(__file__).with_suffix(".svg")
dst.write_text("\n".join(out), encoding="utf-8")
print(f"zapisano {dst}")
