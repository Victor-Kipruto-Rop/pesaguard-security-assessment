import pytest
from pg_assess.rate_limiter import RateLimitExceeded, TargetRateLimiter

def test_target_quota_is_atomic_and_resets_each_minute(tmp_path):
    limiter = TargetRateLimiter(tmp_path / "limits.sqlite3")
    limiter.reserve("target-a", 2, 3, now=120)
    limiter.reserve("target-a", 1, 3, now=121)
    with pytest.raises(RateLimitExceeded):
        limiter.reserve("target-a", 1, 3, now=122)
    limiter.reserve("target-a", 1, 3, now=180)

def test_quota_rejects_run_larger_than_target_limit(tmp_path):
    limiter = TargetRateLimiter(tmp_path / "limits.sqlite3")
    with pytest.raises(RateLimitExceeded):
        limiter.reserve("target-a", 4, 3, now=120)
