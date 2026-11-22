from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Prices:
    input_per_mtok: float
    output_per_mtok: float
    cache_read_per_mtok: float
    cache_write_per_mtok: float

    @classmethod
    def from_mapping(cls, raw: dict) -> "Prices":
        input_price = float(raw["input_per_mtok"])
        output_price = float(raw["output_per_mtok"])
        cache_read = raw.get("cache_read_per_mtok")
        cache_write = raw.get("cache_write_per_mtok")
        return cls(
            input_per_mtok=input_price,
            output_per_mtok=output_price,
            cache_read_per_mtok=float(input_price if cache_read is None else cache_read),
            cache_write_per_mtok=float(input_price if cache_write is None else cache_write),
        )


@dataclass(frozen=True)
class Tokens:
    input: int = 0
    output: int = 0
    cache_read: int = 0
    cache_write: int = 0

    @property
    def total(self) -> int:
        return self.input + self.output + self.cache_read + self.cache_write

    def add(self, other: "Tokens") -> "Tokens":
        return Tokens(
            self.input + other.input,
            self.output + other.output,
            self.cache_read + other.cache_read,
            self.cache_write + other.cache_write,
        )

    def subtract(self, other: "Tokens") -> "Tokens":
        return Tokens(self.input - other.input, self.output - other.output,
                      self.cache_read - other.cache_read, self.cache_write - other.cache_write)

    def contains(self, other: "Tokens") -> bool:
        return all(a >= b for a, b in zip((self.input, self.output, self.cache_read, self.cache_write),
                                           (other.input, other.output, other.cache_read, other.cache_write)))

    def maximum(self, other: "Tokens") -> "Tokens":
        return Tokens(
            max(self.input, other.input),
            max(self.output, other.output),
            max(self.cache_read, other.cache_read),
            max(self.cache_write, other.cache_write),
        )

    def as_usage(self) -> dict[str, int]:
        return {
            "input_tokens": self.input,
            "output_tokens": self.output,
            "cache_read_input_tokens": self.cache_read,
            "cache_creation_input_tokens": self.cache_write,
        }


def price_of(tokens: Tokens, prices: Prices) -> float:
    return (
        tokens.input * prices.input_per_mtok
        + tokens.output * prices.output_per_mtok
        + tokens.cache_read * prices.cache_read_per_mtok
        + tokens.cache_write * prices.cache_write_per_mtok
    ) / 1_000_000


def _mapping(raw: object) -> dict:
    if isinstance(raw, dict):
        return raw
    if hasattr(raw, "__dict__"):
        return dict(vars(raw))
    return {}


def _num(raw: dict, *keys: str) -> int:
    for key in keys:
        value = raw.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return 0


def _optional_num(raw: dict, *keys: str) -> int | None:
    for key in keys:
        if key not in raw or raw[key] is None:
            continue
        try:
            return int(raw[key])
        except (TypeError, ValueError):
            continue
    return None


def tokens_from_usage(usage: object) -> Tokens:
    raw = _mapping(usage)
    return Tokens(
        input=_num(raw, "input_tokens", "inputTokens"),
        output=_num(raw, "output_tokens", "outputTokens"),
        cache_read=_num(raw, "cache_read_input_tokens", "cacheReadInputTokens"),
        cache_write=_num(raw, "cache_creation_input_tokens", "cacheCreationInputTokens"),
    )


@dataclass
class UsageAccumulator:
    """合并流式 usage 的累计快照，并按模型调用去重。"""

    calls: dict[str, Tokens] = field(default_factory=dict)

    @classmethod
    def from_snapshot(cls, raw: object) -> "UsageAccumulator":
        if not isinstance(raw, dict):
            return cls()
        return cls({key: tokens_from_usage(value) for key, value in raw.items() if isinstance(key, str) and isinstance(value, dict)})

    def persistence(self) -> dict:
        return {key: tokens.as_usage() for key, tokens in self.calls.items()}

    @property
    def tokens(self) -> Tokens:
        total = Tokens()
        for tokens in self.calls.values():
            total = total.add(tokens)
        return total

    def clear(self) -> None:
        self.calls.clear()

    def clear_session(self, session_id: str) -> None:
        prefix = session_id + "\0"
        self.calls = {key: value for key, value in self.calls.items() if not key.startswith(prefix)}

    def session_tokens(self, session_id: str) -> Tokens:
        total = Tokens()
        for key, tokens in self.calls.items():
            if key.startswith(session_id + "\0"):
                total = total.add(tokens)
        return total

    def update(self, key: str, usage: object) -> bool:
        raw = _mapping(usage)
        current = self.calls.get(key, Tokens())
        values = {
            "input": _optional_num(raw, "input_tokens", "inputTokens"),
            "output": _optional_num(raw, "output_tokens", "outputTokens"),
            "cache_read": _optional_num(raw, "cache_read_input_tokens", "cacheReadInputTokens"),
            "cache_write": _optional_num(raw, "cache_creation_input_tokens", "cacheCreationInputTokens"),
        }
        if all(value is None for value in values.values()):
            return False
        updated = Tokens(
            input=current.input if values["input"] is None else values["input"],
            output=current.output if values["output"] is None else values["output"],
            cache_read=current.cache_read if values["cache_read"] is None else values["cache_read"],
            cache_write=current.cache_write if values["cache_write"] is None else values["cache_write"],
        )
        self.calls[key] = updated
        return updated != current

    def update_stream(self, key: str, event: object) -> bool:
        raw = _mapping(event)
        event_type = raw.get("type")
        if event_type == "message_start":
            message = _mapping(raw.get("message"))
            return self.update(key, message.get("usage"))
        if event_type == "message_delta":
            return self.update(key, raw.get("usage"))
        return False


def summarize_model_usage(model_usage: object, prices: Prices) -> tuple[Tokens, float] | None:
    """model_usage 是会话累计值。费用按调用方设定的单价计算，不用 SDK 自带的 costUSD。"""
    if not isinstance(model_usage, dict) or not model_usage:
        return None
    total = Tokens()
    cost = 0.0
    for raw in model_usage.values():
        tokens = tokens_from_usage(raw)
        total = total.add(tokens)
        cost += price_of(tokens, prices)
    return total, cost


@dataclass
class Ledger:
    """把同一会话里的累计用量，和会话重开后的新累计，合成任务总花费。"""

    frozen_tokens: Tokens = field(default_factory=Tokens)
    frozen_cost: float = 0.0
    current_tokens: Tokens = field(default_factory=Tokens)
    current_cost: float = 0.0
    mode: str | None = None
    session_baselines: dict[str, Tokens] = field(default_factory=dict)
    legacy_session: str | None = None
    settled_result_ids: set[str] = field(default_factory=set)

    @classmethod
    def from_snapshot(cls, raw: dict) -> "Ledger":
        settled = raw.get("usage_settled")
        values = settled if isinstance(settled, dict) else raw
        tokens = Tokens(
            input=int(values.get("input_tokens") or 0),
            output=int(values.get("output_tokens") or 0),
            cache_read=int(values.get("cache_read_tokens") or 0),
            cache_write=int(values.get("cache_write_tokens") or 0),
        )
        cost = float(values.get("spent") or 0.0)
        mode = "absolute" if tokens.total or cost else None
        baselines = raw.get("usage_baselines")
        if isinstance(baselines, dict):
            session_baselines = {
                session_id: tokens_from_usage(usage)
                for session_id, usage in baselines.items()
                if isinstance(session_id, str) and isinstance(usage, dict)
            }
            legacy_session = raw.get("usage_legacy_session")
        else:
            session_baselines = {}
            baseline_usage = raw.get("usage_baseline")
            baseline_session = raw.get("usage_baseline_session")
            if isinstance(baseline_session, str) and isinstance(baseline_usage, dict):
                session_baselines[baseline_session] = tokens_from_usage(baseline_usage)
            # Older snapshots could retain a selector's baseline instead of the main session's.
            legacy_session = raw.get("session_id")
        legacy_session = str(legacy_session) if legacy_session else None
        result_ids = raw.get("usage_result_ids")
        settled_result_ids = {value for value in result_ids if isinstance(value, str)} if isinstance(result_ids, list) else set()
        return cls(
            current_tokens=tokens,
            current_cost=cost,
            mode=mode,
            session_baselines=session_baselines,
            legacy_session=None if legacy_session in session_baselines else legacy_session,
            settled_result_ids=settled_result_ids,
        )

    def settle_session(
        self, session_id: str, tokens: Tokens, prices: Prices, observed: Tokens, *, resumed: bool = False,
    ) -> bool:
        """Apply only usage since the last result; legacy resumes use observed new calls."""
        baseline = self.session_baselines.get(session_id)
        checkpoint = tokens
        reliable = True
        if baseline is None:
            delta = observed if self.legacy_session == session_id else tokens
            reliable = self.legacy_session != session_id or bool(observed.total)
        elif tokens.contains(baseline):
            delta = tokens.subtract(baseline)
        elif resumed and observed.total and tokens == observed:
            # A resumed SDK client can start its counters from zero. The new calls explain the entire result.
            delta = tokens
        else:
            # A stale or partial snapshot must not lower any charged counter.
            checkpoint = baseline.maximum(tokens)
            delta = checkpoint.subtract(baseline)
            reliable = False
        total = self.tokens.add(delta)
        cost = self.spent + price_of(delta, prices)
        self.frozen_tokens, self.frozen_cost = Tokens(), 0.0
        self.current_tokens, self.current_cost, self.mode = total, cost, "absolute"
        self.session_baselines[session_id] = checkpoint
        if self.legacy_session == session_id:
            self.legacy_session = None
        return reliable

    def settle_delta(self, session_id: str, tokens: Tokens, prices: Prices) -> None:
        total, cost = self.tokens.add(tokens), self.spent + price_of(tokens, prices)
        self.frozen_tokens, self.frozen_cost = Tokens(), 0.0
        self.current_tokens, self.current_cost, self.mode = total, cost, "absolute"
        # A later cumulative result includes this usage. Keep unknown legacy totals unresolved.
        if session_id and session_id != self.legacy_session:
            baseline = self.session_baselines.get(session_id, Tokens())
            self.session_baselines[session_id] = baseline.add(tokens)

    @property
    def spent(self) -> float:
        return self.frozen_cost + self.current_cost

    @property
    def tokens(self) -> Tokens:
        return self.frozen_tokens.add(self.current_tokens)

    def apply_absolute(self, tokens: Tokens, cost: float) -> None:
        if self.mode == "delta":
            self.current_tokens = Tokens()
            self.current_cost = 0.0
        self.mode = "absolute"
        if tokens.total < self.current_tokens.total:
            self.frozen_tokens = self.frozen_tokens.add(self.current_tokens)
            self.frozen_cost += self.current_cost
        self.current_tokens = tokens
        self.current_cost = cost

    def apply_delta(self, tokens: Tokens, prices: Prices) -> None:
        if self.mode == "absolute":
            return
        self.mode = "delta"
        self.current_tokens = self.current_tokens.add(tokens)
        self.current_cost += price_of(tokens, prices)

    def snapshot(self) -> dict[str, float | int]:
        tokens = self.tokens
        result = {
            "spent": self.spent,
            "input_tokens": tokens.input,
            "output_tokens": tokens.output,
            "cache_read_tokens": tokens.cache_read,
            "cache_write_tokens": tokens.cache_write,
        }
        return result

    def persistence(self) -> dict:
        return {
            "usage_settled": self.snapshot(),
            "usage_baselines": {session_id: tokens.as_usage() for session_id, tokens in self.session_baselines.items()},
            "usage_legacy_session": self.legacy_session,
            "usage_result_ids": sorted(self.settled_result_ids),
        }
