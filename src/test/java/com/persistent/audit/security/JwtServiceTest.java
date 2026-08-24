package com.persistent.audit.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.persistent.audit.exceptions.JwtAuthenticationException;
import com.persistent.audit.model.User;

class JwtServiceTest {

	private static final String SECRET = "audit-log-service-hs256-secret-key-32";
	private JwtService jwtService;
	private User user;

	@BeforeEach
	void setUp() {
		jwtService = new JwtService(SECRET, 3_600_000L);
		user = new User(1L, "admin", "ADMIN", "admin@example.com", "hash");
	}

	@Test
	void generateAndParseRoundTrip() throws Exception {
		String token = jwtService.generateToken(user);
		assertThat(jwtService.getExpirationMs()).isEqualTo(3_600_000L);
		assertThat(jwtService.extractUsername(token)).isEqualTo("admin");
		assertThat(jwtService.parseAndValidate(token).getStringClaim("email")).isEqualTo("admin@example.com");
		assertThat(jwtService.parseAndValidate(token).getStringClaim("userType")).isEqualTo("ADMIN");
	}

	@Test
	void expiredTokenIsRejected() {
		String token = jwtService.generateToken(user, Instant.now().minusSeconds(120), 1_000L);
		assertThatThrownBy(() -> jwtService.parseAndValidate(token))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("expired");
	}

	@Test
	void malformedTokenIsRejected() {
		assertThatThrownBy(() -> jwtService.parseAndValidate("not-a-jwt"))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("Invalid JWT");
	}

	@Test
	void tokenSignedWithDifferentSecretIsRejected() throws Exception {
		JwtService other = new JwtService("other-secret-must-be-32-bytes-long!", 3_600_000L);
		String token = other.generateToken(user);
		assertThatThrownBy(() -> jwtService.parseAndValidate(token))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("signature");
	}

	@Test
	void missingSubjectIsRejected() throws Exception {
		JWTClaimsSet claims = new JWTClaimsSet.Builder()
				.expirationTime(java.util.Date.from(Instant.now().plusSeconds(60)))
				.build();
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
		jwt.sign(new MACSigner(SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
		assertThatThrownBy(() -> jwtService.parseAndValidate(jwt.serialize()))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("subject");
	}

	@Test
	void missingExpirationAndBlankSubjectAreRejected() throws Exception {
		JWTClaimsSet noExp = new JWTClaimsSet.Builder().subject("admin").build();
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), noExp);
		jwt.sign(new MACSigner(SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
		assertThatThrownBy(() -> jwtService.parseAndValidate(jwt.serialize()))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("expired");

		JWTClaimsSet blankSubject = new JWTClaimsSet.Builder()
				.subject("  ")
				.expirationTime(java.util.Date.from(Instant.now().plusSeconds(60)))
				.build();
		SignedJWT blankJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), blankSubject);
		blankJwt.sign(new MACSigner(SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
		assertThatThrownBy(() -> jwtService.parseAndValidate(blankJwt.serialize()))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("subject");
	}

	@Test
	void generateTokenFailsWhenSecretTooShort() {
		JwtService shortSecret = new JwtService("tiny", 1000L);
		assertThatThrownBy(() -> shortSecret.generateToken(user))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("Unable to create JWT");
	}
}
