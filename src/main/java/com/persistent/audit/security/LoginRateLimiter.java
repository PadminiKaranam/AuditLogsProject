package com.persistent.audit.security;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.persistent.audit.exceptions.TooManyRequestsException;

@Component
public class LoginRateLimiter {

	private final Clock clock;
	private final int maxFailedAttempts;
	private final Duration window;
	private final ConcurrentHashMap<String, AttemptState> attempts = new ConcurrentHashMap<>();

	public LoginRateLimiter(
			Clock clock,
			@Value("${audit.login.rate-limit.max-failed-attempts:5}") int maxFailedAttempts,
			@Value("${audit.login.rate-limit.window-ms:900000}") long windowMs) {
		this.clock = clock;
		this.maxFailedAttempts = maxFailedAttempts;
		this.window = Duration.ofMillis(windowMs);
	}

	public void check(String username, String clientIp) {
		AttemptState state = attempts.get(key(username, clientIp));
		if (state == null) {
			return;
		}
		Instant now = clock.instant();
		if (now.isAfter(state.windowStart.plus(window))) {
			attempts.remove(key(username, clientIp), state);
			return;
		}
		if (state.failures >= maxFailedAttempts) {
			throw new TooManyRequestsException("Too Many Requests");
		}
	}

	public void recordFailure(String username, String clientIp) {
		String mapKey = key(username, clientIp);
		attempts.compute(mapKey, (ignored, existing) -> {
			Instant now = clock.instant();
			if (existing == null || now.isAfter(existing.windowStart.plus(window))) {
				return new AttemptState(now, 1);
			}
			return new AttemptState(existing.windowStart, existing.failures + 1);
		});
	}

	public void reset(String username, String clientIp) {
		attempts.remove(key(username, clientIp));
	}

	private String key(String username, String clientIp) {
		String user = StringUtils.hasText(username) ? username.trim().toLowerCase() : "unknown";
		String ip = StringUtils.hasText(clientIp) ? clientIp : "unknown";
		return user + "|" + ip;
	}

	private static final class AttemptState {
		private final Instant windowStart;
		private final int failures;

		private AttemptState(Instant windowStart, int failures) {
			this.windowStart = windowStart;
			this.failures = failures;
		}
	}
}
