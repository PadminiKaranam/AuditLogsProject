package com.persistent.audit.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

class SecurityConfigTest {

	@Test
	void passwordEncoderBeanProducesBcryptHash() {
		SecurityConfig config = new SecurityConfig(null);
		assertThat(config.passwordEncoder().matches("secret", config.passwordEncoder().encode("secret"))).isTrue();
	}

	@Test
	void corsAllowlistDoesNotUseWildcardAndDisallowsCredentials() {
		CorsConfigurationSource source = new SecurityConfig(null).corsConfigurationSource();
		CorsConfiguration configuration = source.getCorsConfiguration(new MockHttpServletRequest("GET", "/audit/export"));

		assertThat(configuration.getAllowedOrigins())
				.containsExactly("http://localhost:8080", "http://localhost:8081", "http://localhost:8082")
				.doesNotContain("*");
		assertThat(configuration.getAllowedOriginPatterns()).isNullOrEmpty();
		assertThat(configuration.getAllowedMethods()).containsExactly("GET", "PUT", "POST");
		assertThat(configuration.getAllowedHeaders()).containsExactly("Authorization");
		assertThat(configuration.getExposedHeaders()).containsExactly("Content-Disposition");
		assertThat(configuration.getAllowCredentials()).isFalse();
		assertThat(configuration.getMaxAge()).isEqualTo(3600L);
		assertThat(configuration.checkOrigin("http://evil.example")).isNull();
		assertThat(configuration.checkOrigin("http://localhost:8081")).isEqualTo("http://localhost:8081");
	}

	@Test
	void writeJsonUsesStatusAndMessage() throws Exception {
		MockHttpServletResponse response = new MockHttpServletResponse();
		SecurityConfig.writeJson(response, HttpStatus.FORBIDDEN, "Access Forbidden");
		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getContentAsString()).isEqualTo("{\"status\":403,\"error\":\"Access Forbidden\"}");
	}
}
