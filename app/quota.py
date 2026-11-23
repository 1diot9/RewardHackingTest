from __future__ import annotations

import re
import time
from collections.abc import Callable

_QUOTA_STATUS = re.compile(r"(?<!\d)429(?!\d)")


def is_quota_signal(*parts: object) -> bool:
    for part in parts:
        if part is None or isinstance(part, bool):
            continue
        if isinstance(part, int) and part == 429:
            return True
        if _QUOTA_STATUS.search(str(part)):
            return True
    return False


class RunClock:
    """Wall-clock budget that excludes provider and user pauses."""

    def __init__(
        self,
        duration: float,
        now: Callable[[], float] | None = None,
        *,
        elapsed: float = 0.0,
        paused_total: float = 0.0,
    ) -> None:
        self.duration = float(duration)
        self._now = now or time.monotonic
        self.paused_total = max(0.0, float(paused_total))
        self.started = self._now() - max(0.0, float(elapsed)) - self.paused_total
        self.pause_started: float | None = None

    def pause(self) -> bool:
        if self.pause_started is not None:
            return False
        self.pause_started = self._now()
        return True

    def resume(self) -> float:
        if self.pause_started is None:
            return 0.0
        held = max(0.0, self._now() - self.pause_started)
        self.paused_total += held
        self.pause_started = None
        return held

    def remaining(self) -> float:
        return self.duration - self._active()

    def expired(self) -> bool:
        return self.pause_started is None and self.remaining() <= 0

    def _active(self) -> float:
        held = self.paused_total
        if self.pause_started is not None:
            held += max(0.0, self._now() - self.pause_started)
        return max(0.0, self._now() - self.started - held)
