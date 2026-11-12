"""pydecomp - proof model.

A recovery result without evidence is a claim.  This module is the evidence:
every run builds one :class:`Proof` and it is written next to the output as
``.proof.json`` (machine-checkable) and ``.proof.md`` (readable).

The schema is deliberately boring so anything can consume it::

    {"tool": "pydecomp 10.0.0",
     "input": {"name": ..., "sha256": ..., "bytes": N},
     "layers": [{"depth": 1, "transform": "base64", "backend": ..., "verified": true}],
     "tiers": {"semantic": [...], "structural": [], "syntactic": [], "unverified": []},
     "inferred": [{"region": ..., "reason": ..., "confidence": 0.91}],
     "lost": [...],
     "guarantee": "no input byte was executed, imported, or compiled"}

Nothing in here talks to the filesystem; :mod:`pydecomp.proof.write` does that.
"""
from __future__ import annotations

#: strongest first.  A module is reported at the *weakest* tier it needs.
TIER_ORDER = ("semantic", "structural", "syntactic", "unverified")

TIER_MEANING = {
    "semantic": "recompiles to the same instruction stream as the original",
    "structural": "same control-flow shape and constant table, encoding differs",
    "syntactic": "compiles, equivalence not proven",
    "unverified": "does not compile - kept because dropping it loses code",
}

GUARANTEE = "no input byte was executed, imported, or compiled"

#: the tier prefixes a recovered file carries when it is *not* semantic
TIER_PREFIX = {
    "structural": "# STRUCTURAL - equivalent control flow, encoding differs\n",
    "syntactic": "# UNVERIFIED - compiles, equivalence not proven\n",
    "unverified": "# UNVERIFIED - does not compile on this interpreter\n",
}


class Layer:
    """One transformation in the chain from input bytes to output text."""

    __slots__ = ("depth", "transform", "backend", "verified", "target", "detail")

    def __init__(self, depth: int, transform: str, backend: str = "",
                 verified: bool = True, target: str | None = None,
                 detail: str = ""):
        self.depth = depth
        self.transform = transform
        self.backend = backend
        self.verified = verified
        self.target = target
        self.detail = detail

    def as_dict(self) -> dict:
        out = {"depth": self.depth, "transform": self.transform,
               "backend": self.backend, "verified": bool(self.verified)}
        if self.target:
            out["target"] = self.target
        if self.detail:
            out["detail"] = self.detail
        return out

    def line(self) -> str:
        bits = [f"{self.depth}. {self.transform}"]
        if self.target:
            bits.append(f"on {self.target}")
        if self.backend:
            bits.append(f"via {self.backend}")
        if self.detail:
            bits.append(f"- {self.detail}")
        return " ".join(bits)


class Proof:
    """Everything a reader needs to check one output file."""

    def __init__(self, tool: str, name: str, digest: str, size: int,
                 kind: str = "source"):
        self.tool = tool
        self.name = name
        self.digest = digest
        self.size = size
        self.kind = kind
        self.output: dict = {}
        self.layers: list[Layer] = []
        self.tiers: dict[str, list[str]] = {key: [] for key in TIER_ORDER}
        self.evidence: dict[str, str] = {}
        self.inferred: list[dict] = []
        self.lost: list[str] = []
        self.guarantee = GUARANTEE
        self.notes: list[str] = []

    # ---------------------------------------------------------------- layers
    def add_layer(self, transform: str, backend: str = "", verified: bool = True,
                  target: str | None = None, detail: str = "") -> Layer:
        layer = Layer(len(self.layers) + 1, transform, backend, verified, target, detail)
        self.layers.append(layer)
        return layer

    # ----------------------------------------------------------------- tiers
    def mark(self, name: str, tier: str, detail: str = "") -> None:
        """Record the tier one unit of recovered code was proven at."""
        tier = tier if tier in TIER_ORDER else "unverified"
        for key in TIER_ORDER:                      # one home per unit
            if name in self.tiers[key]:
                self.tiers[key].remove(name)
        self.tiers[tier].append(name)
        if detail:
            self.evidence[f"{name}:{tier}"] = detail

    def infer(self, region: str, reason: str, confidence: float) -> None:
        self.inferred.append({"region": region, "reason": reason,
                              "confidence": round(float(confidence), 2)})

    def lose(self, item: str) -> None:
        if item and item not in self.lost:
            self.lost.append(item)

    # --------------------------------------------------------------- summary
    @property
    def counts(self) -> dict:
        return {key: len(value) for key, value in self.tiers.items()}

    @property
    def worst(self) -> str:
        """The weakest tier any recovered unit needed."""
        for key in reversed(TIER_ORDER):
            if self.tiers[key]:
                return key
        return "unverified"

    @property
    def proven(self) -> bool:
        """True when everything recovered is instruction-identical."""
        return bool(self.tiers["semantic"]) and not any(
            self.tiers[key] for key in TIER_ORDER[1:])

    @property
    def percent(self) -> float:
        total = sum(len(self.tiers[key]) for key in TIER_ORDER)
        return 100.0 * len(self.tiers["semantic"]) / total if total else 0.0

    def summary(self) -> str:
        counts = self.counts
        return (f"proven {counts['semantic']}/{sum(counts.values())} units "
                f"({self.percent:.0f}%) · tier {self.worst}")

    # ---------------------------------------------------------------- output
    def as_dict(self) -> dict:
        payload = {
            "tool": self.tool,
            "input": {"name": self.name, "sha256": self.digest, "bytes": self.size},
            "kind": self.kind,
            "layers": [layer.as_dict() for layer in self.layers],
            "tiers": {key: list(value) for key, value in self.tiers.items()},
            "tier_meaning": dict(TIER_MEANING),
            "inferred": list(self.inferred),
            "lost": list(self.lost),
            "guarantee": self.guarantee,
        }
        if self.output:
            payload["output"] = dict(self.output)
        if self.evidence:
            payload["evidence"] = dict(self.evidence)
        if self.notes:
            payload["notes"] = list(self.notes)
        return payload

    def markdown(self) -> str:
        counts = self.counts
        out = [f"# proof - {self.name}", ""]
        out.append(f"`{self.tool}`  ·  input `{self.name}` ({self.size:,} B)  ·  "
                   f"sha256 `{self.digest[:32]}…`")
        out.append("")
        out.append(f"**{self.summary()}**")
        out.append("")
        out.append("| tier | units | meaning |")
        out.append("| --- | --- | --- |")
        for key in TIER_ORDER:
            out.append(f"| {key} | {counts[key]} | {TIER_MEANING[key]} |")
        out.append("")
        out.append("## layers")
        out.append("")
        if self.layers:
            for layer in self.layers:
                out.append(f"- {layer.line()}")
        else:
            out.append("- (input needed no unpacking)")
        out.append("")
        if self.tiers["semantic"]:
            out.append("## instruction-identical")
            out.append("")
            out.append(", ".join(f"`{name}`" for name in self.tiers["semantic"][:40]))
            out.append("")
        others = self.tiers["structural"] + self.tiers["syntactic"] \
            + self.tiers["unverified"]
        if others:
            out.append("## not instruction-identical")
            out.append("")
            for key in TIER_ORDER[1:]:
                for name in self.tiers[key]:
                    why = self.evidence.get(f"{name}:{key}", "")
                    out.append(f"- `{name}` - {key}{': ' + why if why else ''}")
            out.append("")
        if self.inferred:
            out.append("## inferred (marked, not invented)")
            out.append("")
            for item in self.inferred[:60]:
                out.append(f"- {item['region']} - {item['reason']} "
                           f"(confidence {item['confidence']})")
            out.append("")
        if self.lost:
            out.append("## lost in the original encoding")
            out.append("")
            for item in self.lost:
                out.append(f"- {item}")
            out.append("")
        out.append("## guarantee")
        out.append("")
        out.append(self.guarantee)
        out.append("")
        if self.notes:
            out.append("## notes")
            out.append("")
            for note in self.notes:
                out.append(f"- {note}")
            out.append("")
        return "\n".join(out)
