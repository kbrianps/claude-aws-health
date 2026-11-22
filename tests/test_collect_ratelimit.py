import time

from awshealth.collect.ratelimit import RateLimiter, TokenBucket


def test_burst_does_not_wait_then_refills_at_rate():
    b = TokenBucket(rate=50.0, burst=3)
    t0 = time.monotonic()
    for _ in range(3):
        b.acquire()
    assert time.monotonic() - t0 < 0.01
    b.acquire()
    assert time.monotonic() - t0 >= 0.015


def test_buckets_are_per_region_and_service_with_cloudtrail_slower():
    r = RateLimiter()
    assert r.bucket("us-east-1", "ec2") is r.bucket("us-east-1", "ec2")
    assert r.bucket("us-east-1", "ec2") is not r.bucket("sa-east-1", "ec2")
    assert (r.bucket("us-east-1", "ec2").rate, r.bucket("us-east-1", "ec2").burst) == (5.0, 10)
    assert r.bucket("us-east-1", "cloudtrail").rate == 1.0
