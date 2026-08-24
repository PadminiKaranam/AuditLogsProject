package com.persistent.audit.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;

class SecurityConfigTest {

	@Test
	void passwordEncoderBeanProducesBcryptHash() {
		SecurityConfig config = new SecurityConfig(null);
		assertThat(config.passwordEncoder().matches("secret", config.passwordEncoder().encode("secret"))).isTrue();
		assertThat(config.corsConfigurationSource()).isNotNull();
	}

	@Test
	void writeJsonUsesStatusAndMessage() throws Exception {
		MockHttpServletResponse response = new MockHttpServletResponse();
		SecurityConfig.writeJson(response, HttpStatus.FORBIDDEN, "Access Forbidden");
		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getContentAsString()).isEqualTo("{\"status\":403,\"error\":\"Access Forbidden\"}");
	}
}
