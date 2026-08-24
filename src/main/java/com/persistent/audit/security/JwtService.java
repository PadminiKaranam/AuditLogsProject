package com.persistent.audit.security;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.persistent.audit.exceptions.JwtAuthenticationException;
import com.persistent.audit.model.User;

@Service
public class JwtService {

	private final byte[] secret;
	private final long expirationMs;
	private final String issuer;
	private final String audience;

	public JwtService(
			@Value("${audit.jwt.secret}") String secret,
			@Value("${audit.jwt.expiration-ms}") long expirationMs,
			@Value("${audit.jwt.issuer}") String issuer,
			@Value("${audit.jwt.audience}") String audience) {
		this.secret = secret.getBytes(StandardCharsets.UTF_8);
		this.expirationMs = expirationMs;
		this.issuer = issuer;
		this.audience = audience;
	}

	public long getExpirationMs() {
		return expirationMs;
	}

	public String generateToken(User user) {
		return generateToken(user, Instant.now(), expirationMs);
	}

	public String generateToken(User user, Instant issuedAt, long ttlMs) {
		try {
			JWTClaimsSet claims = new JWTClaimsSet.Builder()
					.subject(user.getUsername())
					.issuer(issuer)
					.audience(audience)
					.jwtID(UUID.randomUUID().toString())
					.claim("email", user.getUserEmail())
					.claim("userType", user.getUserType())
					.issueTime(Date.from(issuedAt))
					.expirationTime(Date.from(issuedAt.plusMillis(ttlMs)))
					.build();
			SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
			jwt.sign(new MACSigner(secret));
			return jwt.serialize();
		} catch (JOSEException ex) {
			throw new JwtAuthenticationException("Unable to create JWT", ex);
		}
	}

	public JWTClaimsSet parseAndValidate(String token) {
		try {
			SignedJWT jwt = SignedJWT.parse(token);
			if (!jwt.verify(new MACVerifier(secret))) {
				throw new JwtAuthenticationException("Invalid JWT signature");
			}
			JWTClaimsSet claims = jwt.getJWTClaimsSet();
			Date expiration = claims.getExpirationTime();
			if (expiration == null || expiration.before(new Date())) {
				throw new JwtAuthenticationException("JWT has expired");
			}
			if (claims.getSubject() == null || claims.getSubject().isBlank()) {
				throw new JwtAuthenticationException("JWT subject is missing");
			}
			if (!StringUtils.hasText(claims.getIssuer()) || !issuer.equals(claims.getIssuer())) {
				throw new JwtAuthenticationException("Invalid JWT issuer");
			}
			List<String> audiences = claims.getAudience();
			if (audiences == null || !audiences.contains(audience)) {
				throw new JwtAuthenticationException("Invalid JWT audience");
			}
			if (!StringUtils.hasText(claims.getJWTID())) {
				throw new JwtAuthenticationException("JWT ID is missing");
			}
			return claims;
		} catch (JwtAuthenticationException ex) {
			throw ex;
		} catch (Exception ex) {
			throw new JwtAuthenticationException("Invalid JWT", ex);
		}
	}

	public String extractUsername(String token) {
		return parseAndValidate(token).getSubject();
	}
}
