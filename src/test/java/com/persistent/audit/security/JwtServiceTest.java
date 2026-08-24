package com.persistent.audit.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

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
	private static final String ISSUER = "audit-log-service";
	private static final String AUDIENCE = "audit-api";
	private JwtService jwtService;
	private User user;

	@BeforeEach
	void setUp() {
		jwtService = new JwtService(SECRET, 3_600_000L, ISSUER, AUDIENCE);
		user = new User(1L, "admin", "ADMIN", "admin@example.com", "hash");
	}

	@Test
	void validTokenContainsIssuerAudienceAndJwtId() throws Exception {
		String token = jwtService.generateToken(user);
		JWTClaimsSet claims = jwtService.parseAndValidate(token);
		assertThat(jwtService.getExpirationMs()).isEqualTo(3_600_000L);
		assertThat(jwtService.extractUsername(token)).isEqualTo("admin");
		assertThat(claims.getIssuer()).isEqualTo(ISSUER);
		assertThat(claims.getAudience()).containsExactly(AUDIENCE);
		assertThat(claims.getJWTID()).isNotBlank();
		assertThat(claims.getStringClaim("email")).isEqualTo("admin@example.com");
		assertThat(claims.getStringClaim("userType")).isEqualTo("ADMIN");
	}

	@Test
	void missingIssuerIsRejected() throws Exception {
		assertThatThrownBy(() -> jwtService.parseAndValidate(signed(baseClaims().build())))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("issuer");
	}

	@Test
	void wrongIssuerIsRejected() throws Exception {
		assertThatThrownBy(() -> jwtService.parseAndValidate(signed(baseClaims().issuer("other-issuer").build())))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("issuer");
	}

	@Test
	void missingAudienceIsRejected() throws Exception {
		JWTClaimsSet claims = new JWTClaimsSet.Builder()
				.subject("admin")
				.issuer(ISSUER)
				.jwtID(UUID.randomUUID().toString())
				.expirationTime(Date.from(Instant.now().plusSeconds(60)))
				.build();
		assertThatThrownBy(() -> jwtService.parseAndValidate(signed(claims)))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("audience");
	}

	@Test
	void wrongAudienceIsRejected() throws Exception {
		assertThatThrownBy(() -> jwtService.parseAndValidate(
				signed(baseClaims().issuer(ISSUER).audience("other-api").build())))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("audience");
	}

	@Test
	void missingJwtIdIsRejected() throws Exception {
		JWTClaimsSet claims = new JWTClaimsSet.Builder()
				.subject("admin")
				.issuer(ISSUER)
				.audience(AUDIENCE)
				.expirationTime(Date.from(Instant.now().plusSeconds(60)))
				.build();
		assertThatThrownBy(() -> jwtService.parseAndValidate(signed(claims)))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("JWT ID");
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
		JwtService other = new JwtService("other-secret-must-be-32-bytes-long!", 3_600_000L, ISSUER, AUDIENCE);
		String token = other.generateToken(user);
		assertThatThrownBy(() -> jwtService.parseAndValidate(token))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("signature");
	}

	@Test
	void missingSubjectIsRejected() throws Exception {
		JWTClaimsSet claims = baseClaims()
				.issuer(ISSUER)
				.subject(null)
				.build();
		assertThatThrownBy(() -> jwtService.parseAndValidate(signed(claims)))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("subject");
	}

	@Test
	void missingExpirationAndBlankSubjectAreRejected() throws Exception {
		JWTClaimsSet noExp = baseClaims().issuer(ISSUER).expirationTime(null).build();
		assertThatThrownBy(() -> jwtService.parseAndValidate(signed(noExp)))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("expired");

		JWTClaimsSet blankSubject = baseClaims().issuer(ISSUER).subject("  ").build();
		assertThatThrownBy(() -> jwtService.parseAndValidate(signed(blankSubject)))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("subject");
	}

	@Test
	void generateTokenFailsWhenSecretTooShort() {
		JwtService shortSecret = new JwtService("tiny", 1000L, ISSUER, AUDIENCE);
		assertThatThrownBy(() -> shortSecret.generateToken(user))
				.isInstanceOf(JwtAuthenticationException.class)
				.hasMessageContaining("Unable to create JWT");
	}

	private JWTClaimsSet.Builder baseClaims() {
		return new JWTClaimsSet.Builder()
				.subject("admin")
				.audience(AUDIENCE)
				.jwtID(UUID.randomUUID().toString())
				.expirationTime(Date.from(Instant.now().plusSeconds(60)));
	}

	private String signed(JWTClaimsSet claims) throws Exception {
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
		jwt.sign(new MACSigner(SECRET.getBytes(StandardCharsets.UTF_8)));
		return jwt.serialize();
	}
}
