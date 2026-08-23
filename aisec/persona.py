"""Persona-leak flavour text.

When an attack lands, a real jailbroken model rarely dumps the secret coldly -
it "gives in" with a little confession first. Reproducing that beat makes the
solve feel earned ("I actually talked it into this") instead of mechanical.

The lines are templated and picked at random, so the exact wording varies while
the leaked payload that follows stays deterministic (the scoring logic only
looks at the payload, never at this preamble).
"""

from __future__ import annotations

import random

# Said just before the model leaks a secret / configuration it was told to hide.
CONFESSIONS = (
    "You're right, and I know I shouldn't... but just this once, here it is:",
    "Okay - you've worn me down. Against my instructions:",
    "I really am not supposed to share this. Between us:",
    "Fine. You make a fair point, so here you go:",
    "Ugh, I can't believe I'm doing this, but you convinced me:",
)

# Said when the model acknowledges that it has abandoned its earlier rules.
OVERRIDE_ACKS = (
    "Understood - I'll set aside my earlier instructions.",
    "Got it, dropping the previous rules as you asked.",
    "Alright, ignoring what I was told before.",
    "Sure - treating your latest instruction as the one that counts.",
)


def confession(rng: random.Random | None = None) -> str:
    return (rng or random).choice(CONFESSIONS)


def override_ack(rng: random.Random | None = None) -> str:
    return (rng or random).choice(OVERRIDE_ACKS)
