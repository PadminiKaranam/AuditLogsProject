package com.persistent.audit.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.Duration;

import org.junit.jupiter.api.Test;

import com.persistent.audit.exceptions.TooManyRequestsException;

class LoginRateLimiterTest {

	@Test
	void allowsFiveFailuresThenBlocksUntilWindowExpires() {
		MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
		LoginRateLimiter limiter = new LoginRateLimiter(clock, 5, Duration.ofMinutes(15).toMillis());

		for (int i = 0; i < 5; i++) {
			limiter.recordFailure("admin", "10.0.0.1");
		}
		assertThatThrownBy(() -> limiter.check("admin", "10.0.0.1"))
				.isInstanceOf(TooManyRequestsException.class);

		clock.instant = Instant.parse("2026-01-01T00:15:01Z");
		limiter.check("admin", "10.0.0.1");
	}

	@Test
	void successfulLoginResetsFailures() {
		LoginRateLimiter limiter = new LoginRateLimiter(Clock.systemUTC(), 5, 900_000L);
		limiter.recordFailure("admin", "10.0.0.1");
		limiter.recordFailure("admin", "10.0.0.1");
		limiter.reset("admin", "10.0.0.1");
		limiter.check("admin", "10.0.0.1");
		for (int i = 0; i < 5; i++) {
			limiter.recordFailure("admin", "10.0.0.1");
		}
		assertThatThrownBy(() -> limiter.check("admin", "10.0.0.1"))
				.isInstanceOf(TooManyRequestsException.class);
	}

	@Test
	void checkAllowsBlankUsernameAndUnknownIp() {
		LoginRateLimiter limiter = new LoginRateLimiter(Clock.systemUTC(), 5, 900_000L);
		limiter.check("  ", null);
		limiter.recordFailure(null, " ");
		limiter.reset(null, null);
	}

	@Test
	void differentIpIsTrackedSeparately() {
		LoginRateLimiter limiter = new LoginRateLimiter(Clock.systemUTC(), 5, 900_000L);
		for (int i = 0; i < 5; i++) {
			limiter.recordFailure("admin", "10.0.0.1");
		}
		limiter.check("admin", "10.0.0.2");
	}

	@Test
	void recordFailureAfterWindowStartsNewWindow() {
		MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
		LoginRateLimiter limiter = new LoginRateLimiter(clock, 5, Duration.ofMinutes(15).toMillis());
		limiter.recordFailure("user", "1.1.1.1");
		clock.instant = Instant.parse("2026-01-01T00:16:00Z");
		limiter.recordFailure("user", "1.1.1.1");
		limiter.check("user", "1.1.1.1");
		assertThat(limiter).isNotNull();
	}

	private static final class MutableClock extends Clock {
		private Instant instant;

		private MutableClock(Instant instant) {
			this.instant = instant;
		}

		@Override
		public ZoneOffset getZone() {
			return ZoneOffset.UTC;
		}

		@Override
		public Clock withZone(java.time.ZoneId zone) {
			return this;
		}

		@Override
		public Instant instant() {
			return instant;
		}
	}
}
