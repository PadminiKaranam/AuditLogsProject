package com.persistent.audit.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.persistent.audit.model.User;
import com.persistent.audit.repository.UserRepository;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityRegressionTest {

	private static final String SECRET = "audit-log-service-hs256-secret-key-32";

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@BeforeEach
	void ensureUsers() {
		ensureUser("admin", "ADMIN", "admin@example.com", "Admin@123");
		ensureUser("regulator", "REGULATOR", "regulator@example.com", "Regulator@123");
		ensureUser("viewer", "USER", "viewer@example.com", "User@123");
	}

	@Test
	void loginRateLimitReturns429AfterFiveFailuresWithoutRevealingUser() throws Exception {
		for (int i = 0; i < 5; i++) {
			mockMvc.perform(post("/audit/auth/login")
					.with(request -> {
						request.setRemoteAddr("203.0.113.50");
						return request;
					})
					.contentType(MediaType.APPLICATION_JSON)
					.content("{\"username\":\"no-such-user\",\"password\":\"wrong\"}"))
					.andExpect(status().isUnauthorized())
					.andExpect(jsonPath("$.error").value("Invalid username or password"));
		}
		mockMvc.perform(post("/audit/auth/login")
				.with(request -> {
					request.setRemoteAddr("203.0.113.50");
					return request;
				})
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"username\":\"no-such-user\",\"password\":\"wrong\"}"))
				.andExpect(status().isTooManyRequests())
				.andExpect(jsonPath("$.error").value("Too Many Requests"));
	}

	@Test
	void oversizedJsonBodyIsRejectedWith413() throws Exception {
		String token = login("admin", "Admin@123");
		byte[] oversized = new byte[1_048_577];
		mockMvc.perform(post("/audit/createEvent")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content(oversized))
				.andExpect(status().isPayloadTooLarge())
				.andExpect(jsonPath("$.error").value("Payload Too Large"));
	}

	@Test
	void tokenMissingIssuerIsUnauthorizedOnEveryProtectedEndpoint() throws Exception {
		String token = signed(baseClaims().build());
		assertUnauthorizedOnAllEndpoints(token);
	}

	@Test
	void tokenWithWrongAudienceIsUnauthorized() throws Exception {
		String token = signed(baseClaims().issuer("audit-log-service").audience("other-api").build());
		mockMvc.perform(get("/audit/events").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void viewerIsDeniedOnAllAuditEndpoints() throws Exception {
		String token = login("viewer", "User@123");
		mockMvc.perform(post("/audit/createEvent").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"eventType\":\"LOGIN\",\"actorId\":\"a\",\"resourceType\":\"SESSION\",\"resourceId\":\"s\",\"payload\":\"{}\"}"))
				.andExpect(status().isForbidden());
		mockMvc.perform(get("/audit/verify").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isForbidden());
		mockMvc.perform(put("/audit/checkForRetention").header(HttpHeaders.AUTHORIZATION, "Bearer " + token).param("days", "1"))
				.andExpect(status().isForbidden());
		mockMvc.perform(put("/audit/redact").header(HttpHeaders.AUTHORIZATION, "Bearer " + token).param("id", "1").param("fields", "n"))
				.andExpect(status().isForbidden());
		mockMvc.perform(get("/audit/events").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isForbidden());
		mockMvc.perform(get("/audit/export").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isForbidden());
	}

	private void assertUnauthorizedOnAllEndpoints(String token) throws Exception {
		mockMvc.perform(get("/audit/events").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isUnauthorized());
		mockMvc.perform(get("/audit/verify").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isUnauthorized());
		mockMvc.perform(get("/audit/export").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isUnauthorized());
		mockMvc.perform(put("/audit/checkForRetention").header(HttpHeaders.AUTHORIZATION, "Bearer " + token).param("days", "1"))
				.andExpect(status().isUnauthorized());
		mockMvc.perform(put("/audit/redact").header(HttpHeaders.AUTHORIZATION, "Bearer " + token).param("id", "1").param("fields", "n"))
				.andExpect(status().isUnauthorized());
		mockMvc.perform(post("/audit/createEvent").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"eventType\":\"LOGIN\",\"actorId\":\"a\",\"resourceType\":\"SESSION\",\"resourceId\":\"s\",\"payload\":\"{}\"}"))
				.andExpect(status().isUnauthorized());
	}

	private JWTClaimsSet.Builder baseClaims() {
		return new JWTClaimsSet.Builder()
				.subject("admin")
				.audience("audit-api")
				.jwtID(UUID.randomUUID().toString())
				.expirationTime(Date.from(Instant.now().plusSeconds(60)));
	}

	private String signed(JWTClaimsSet claims) throws Exception {
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
		jwt.sign(new MACSigner(SECRET.getBytes(StandardCharsets.UTF_8)));
		return jwt.serialize();
	}

	private void ensureUser(String username, String userType, String email, String rawPassword) {
		User user = userRepository.findByUsername(username).orElseGet(User::new);
		user.setUsername(username);
		user.setUserType(userType);
		user.setUserEmail(email);
		if (user.getPassword() == null || user.getPassword().isBlank()) {
			user.setPassword(passwordEncoder.encode(rawPassword));
		}
		userRepository.save(user);
	}

	private String login(String username, String password) throws Exception {
		String json = mockMvc.perform(post("/audit/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
				.andExpect(status().isOk())
				.andReturn()
				.getResponse()
				.getContentAsString();
		int start = json.indexOf("\"accessToken\":\"") + "\"accessToken\":\"".length();
		return json.substring(start, json.indexOf('"', start));
	}
}
