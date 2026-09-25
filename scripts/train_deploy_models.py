"""
train_deploy_models.py
-----------------------
Trains the LIVE WAF's models (models/deploy/). The paper's models
(models/*.joblib) and every paper number are untouched.

Why: the paper's benign data comes from templates with 29 parameter names.
On real traffic the paper models flag ordinary inputs whose parameter name
they never saw (e.g. "type=1", "key=x"). Here the same paper training
split (data/processed/train.csv) is combined with seeded, diverse benign
inputs built from 6,453 real parameter names (data/deploy/param_names.txt)
and realistic values: numbers, single letters, dates, e-mails, UUIDs,
tokens, paths, and short natural sentences (with apostrophes and everyday
words such as "select", "order", "from").

Held out, never trained on: 20% of the parameter names (seeded), the
paper test split, CSIC 2010, PayloadsAllTheThings, and sqlmap traffic.

Each training attack is also placed inside parameter contexts
("name=<payload>", "a=1&b=<payload>") so that input shape is not a label
shortcut. Inputs are canonicalized exactly as the WAF does (waf_views)
before training, so training and inference see the same representation.

Run:
    python scripts/train_deploy_models.py
"""

from __future__ import annotations

import json
import random
import string
import sys
import uuid
from pathlib import Path

import joblib
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.features import build_vectorizer  # noqa: E402
from src.waf_canonical import waf_views  # noqa: E402

SEED = 42
N_BENIGN = 4000
HOLDOUT_FRACTION = 0.2
OUT_DIR = ROOT / "models" / "deploy"

_WORDS = """account address admin alpha amount apple archive article author auto
back basic beta black blog blue book brown budget cancel card cart category
change check city clear close code color comment config contact content copy
country coupon create credit daily dark data date day default delete demo
desc detail device display done down draft edit email end english error event
export false field file filter first form free full gallery general gift
green group guest help hidden high history home hot image import index info
input item key label language large last latest left level light limit link
list live local login logout low main manage map medium menu message mobile
mode month more name new news next none normal note null number off offer
old on open option order other owner page paid password pending phone photo
plan post preview price print private product profile public query quick
random rate read recent red refresh region remove reply report reset result
review right role save search season secret section select send server
setting share shop short show single size small sort source start state
status step stock store style submit summary support system table tag task
team test text theme ticket time title today token top total track true type
update upload user value video view visible week white word year yellow yes
zone""".split()

_SENTENCES = [
    "i'm looking for {w} and {w2}", "don't forget the {w}", "it's a {w} {w2}",
    "please select a {w} from the list", "order by {w} or {w2}", "where is my {w}",
    "can't find the {w} page", "we'll update the {w} tomorrow", "you're on the {w} plan",
    "the {w} and the {w2}", "select {w} or {w2}", "drop me a {w}",
    "my name is {Name} O'{Name2}", "{Name}'s {w}", "is {w} better than {w2}?",
    "table for {n} at {n2}pm", "from {w} to {w2}", "{n} {w} left in stock",
    "hello, i'd like to {w} my {w2}", "rock & roll", "5 stars, would {w} again!",
    "not {w}, just {w2}", "and then the {w}", "{w} - {w2} ({n})",
]
_NAMES = "Anna Budi Chen Dewi Eko Farah Gita Hana Ivan Joko Kim Lina Maria Nina Omar Putri Rudi Sari Tono Wati".split()


# SQL/JS keywords are ordinary values on their own ("sort=order",
# "type=update", "tab=select"); an injection needs syntax around them.
_KEYWORD_VALUES = """select order update delete insert union from where table drop alert
script and or not null true false like join group having case when exec
by into values set limit offset desc asc count sum max min top script
prompt confirm eval document window cookie location""".split()


def _value(rng: random.Random) -> str:
    kind = rng.randrange(15)
    if kind == 14:
        return rng.choice(_KEYWORD_VALUES)
    if kind == 0:
        return str(rng.randrange(10))
    if kind == 1:
        return str(rng.randrange(100000))
    if kind == 2:
        return f"{rng.uniform(0, 1000):.{rng.randrange(1, 3)}f}"
    if kind == 3:
        return rng.choice(string.ascii_letters)
    if kind == 4:
        return rng.choice(_WORDS)
    if kind == 5:
        return rng.choice(["true", "false", "yes", "no", "on", "off", "null", "none", "0", "1"])
    if kind == 6:
        y = rng.randrange(1990, 2031)
        return rng.choice([f"{y}-{rng.randrange(1,13):02d}-{rng.randrange(1,29):02d}", f"{y}-{y + 1}",
                           f"{rng.randrange(1,29):02d}/{rng.randrange(1,13):02d}/{y}"])
    if kind == 7:
        return f"{rng.choice(_WORDS)}{rng.randrange(100)}@example.{rng.choice(['com', 'org', 'id'])}"
    if kind == 8:
        return str(uuid.UUID(int=rng.getrandbits(128)))
    if kind == 9:
        return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(rng.randrange(8, 33)))
    if kind == 10:
        return "/" + "/".join(rng.choice(_WORDS) for _ in range(rng.randrange(1, 4)))
    if kind == 11:
        return f"{rng.choice(_WORDS)}-{rng.choice(_WORDS)}"
    s = rng.choice(_SENTENCES).format(w=rng.choice(_WORDS), w2=rng.choice(_WORDS), n=rng.randrange(1, 20),
                                      n2=rng.randrange(1, 12), Name=rng.choice(_NAMES), Name2=rng.choice(_NAMES))
    return s.capitalize() if rng.random() < 0.5 else s


def split_param_names(seed: int = SEED) -> tuple[list[str], list[str]]:
    names = sorted({n.strip() for n in (ROOT / "data" / "deploy" / "param_names.txt").read_text().splitlines()
                    if n.strip()})
    rng = random.Random(seed)
    rng.shuffle(names)
    k = int(len(names) * HOLDOUT_FRACTION)
    return names[k:], names[:k]          # train, held out


def generate_benign(names: list[str], n: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    out = []
    def name() -> str:
        # keywords are common parameter NAMES too: group=, order=, from=, select=
        return rng.choice(_KEYWORD_VALUES) if rng.random() < 0.08 else rng.choice(names)

    for _ in range(n):
        pairs = [f"{name()}={_value(rng)}" for _ in range(rng.choice([1, 1, 1, 2, 3, 4]))]
        out.append("&".join(pairs) if rng.random() < 0.9 else _value(rng))
    return out


def contextualize_attacks(payloads: list[str], labels: list[str], names: list[str],
                          seed: int) -> tuple[list[str], list[str]]:
    """Each training attack also appears inside parameter contexts.

    The generated benign data is "name=value"-shaped while the paper's
    attacks are bare strings; without this the models learn the shortcut
    "parameter-shaped => benign" and miss attacks sent as form fields
    (measured: paper-split detection fell from 95.8% to 69.5%).
    """
    rng = random.Random(seed)
    X, y = [], []
    for p, lab in zip(payloads, labels):
        X += [p,
              f"{rng.choice(names)}={p}",
              f"{rng.choice(names)}={_value(rng)}&{rng.choice(names)}={p}",
              f"{rng.choice(names)}={p}&{rng.choice(names)}={_value(rng)}"]
        y += [lab] * 4
    return X, y


def build_models() -> dict[str, Pipeline]:
    # Same features and base estimators as the paper; class_weight balances
    # the larger benign set against the attack classes.
    return {
        "logistic_regression": Pipeline([
            ("tfidf", build_vectorizer()),
            ("clf", LogisticRegression(max_iter=2000, C=10.0, class_weight="balanced")),
        ]),
        "svm": Pipeline([
            ("tfidf", build_vectorizer()),
            ("clf", CalibratedClassifierCV(LinearSVC(C=1.0, dual="auto", class_weight="balanced"), cv=3)),
        ]),
    }


def main() -> None:
    train = pd.read_csv(ROOT / "data" / "processed" / "train.csv").dropna(subset=["payload", "label"])
    train_names, heldout_names = split_param_names()
    benign = generate_benign(train_names, N_BENIGN, SEED)

    ben = train[train.label == "benign"]
    att = train[train.label != "benign"]
    X_att, y_att = contextualize_attacks([str(p) for p in att.payload], list(att.label), train_names, SEED + 1)
    X = [str(p) for p in ben.payload] + benign + X_att
    y = ["benign"] * (len(ben) + len(benign)) + y_att
    X_canon = [waf_views(x)[0] for x in X]
    print(f"[deploy] training on {len(X)} samples: {pd.Series(y).value_counts().to_dict()}")
    print(f"[deploy] parameter names: {len(train_names)} train / {len(heldout_names)} held out")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, pipe in build_models().items():
        pipe.fit(X_canon, y)
        joblib.dump(pipe, OUT_DIR / f"{name}.joblib")
        print(f"[deploy] saved {OUT_DIR / (name + '.joblib')}")

    (OUT_DIR / "manifest.json").write_text(json.dumps({
        "seed": SEED, "n_benign_generated": N_BENIGN, "n_paper_train": len(train),
        "attack_contexts_per_payload": 4,
        "holdout_fraction": HOLDOUT_FRACTION, "n_param_names_train": len(train_names),
        "n_param_names_heldout": len(heldout_names), "canonicalization": "waf_views()[0]",
        "not_trained_on": ["data/processed/test_*.csv", "CSIC 2010", "PayloadsAllTheThings", "sqlmap traffic",
                           "held-out parameter names"],
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
