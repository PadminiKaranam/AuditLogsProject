package com.persistent.audit.exceptions;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

class JwtAuthenticationExceptionTest {

	@Test
	void storesMessageAndCause() {
		RuntimeException cause = new RuntimeException("boom");
		JwtAuthenticationException ex = new JwtAuthenticationException("invalid", cause);
		assertThat(ex.getMessage()).isEqualTo("invalid");
		assertThat(ex.getCause()).isSameAs(cause);
	}

	@Test
	void accessForbiddenExceptionMessage() {
		assertThat(new AccessForbiddenException("Access Forbidden").getMessage()).isEqualTo("Access Forbidden");
	}

	@Test
	void apiErrorResponseOmitsFieldsWhenNull() {
		assertThat(ApiErrorResponse.of(HttpStatus.UNAUTHORIZED, "nope", null).getBody())
				.doesNotContainKey("fields");
	}
}
