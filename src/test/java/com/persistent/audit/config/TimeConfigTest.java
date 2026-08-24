package com.persistent.audit.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;

import org.junit.jupiter.api.Test;

class TimeConfigTest {

	@Test
	void clockUsesUtc() {
		Clock clock = new TimeConfig().clock();
		assertThat(clock).isEqualTo(Clock.systemUTC());
	}
}
