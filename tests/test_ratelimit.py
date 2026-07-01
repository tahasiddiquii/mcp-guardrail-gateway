from mcp_guardrail.ratelimit import RateLimiter


def test_allows_up_to_capacity_then_blocks():
    t = [0.0]
    limiter = RateLimiter(clock=lambda: t[0])
    # capacity 3 per minute, no time advance -> 3 allowed, 4th blocked
    assert limiter.allow("k", 3)
    assert limiter.allow("k", 3)
    assert limiter.allow("k", 3)
    assert not limiter.allow("k", 3)


def test_refills_over_time():
    t = [0.0]
    limiter = RateLimiter(clock=lambda: t[0])
    limiter.allow("k", 60)  # drain 1 of 60
    for _ in range(59):
        limiter.allow("k", 60)
    assert not limiter.allow("k", 60)  # bucket empty
    t[0] += 1.0  # one second -> one token back (60/min)
    assert limiter.allow("k", 60)


def test_zero_rate_blocks_everything():
    limiter = RateLimiter(clock=lambda: 0.0)
    assert not limiter.allow("k", 0)
