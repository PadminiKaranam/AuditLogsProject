package com.persistent.audit.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.persistent.audit.model.User;
import com.persistent.audit.repository.UserRepository;

@SpringBootTest
@AutoConfigureMockMvc
class JwtAuthorizationIntegrationTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@BeforeEach
	void ensureUsersExistInDatabase() {
		ensureUser("admin", "ADMIN", "admin@example.com", "Admin@123");
		ensureUser("regulator", "REGULATOR", "regulator@example.com", "Regulator@123");
		ensureUser("viewer", "USER", "viewer@example.com", "User@123");
	}

	@Test
	void loginSuccessAndAdminCanCreateEvent() throws Exception {
		String token = login("admin", "Admin@123");
		mockMvc.perform(post("/audit/createEvent")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"eventType":"LOGIN","actorId":"actor-1","resourceType":"SESSION","resourceId":"s-1","payload":"{}"}
						"""))
				.andExpect(status().isCreated());
	}

	@Test
	void loginRejectsBadPassword() throws Exception {
		mockMvc.perform(post("/audit/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"username":"admin","password":"wrong"}
						"""))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void loginRejectsUnknownUsernameAgainstUsersTable() throws Exception {
		mockMvc.perform(post("/audit/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"username":"does-not-exist","password":"anything"}
						"""))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void missingBearerTokenIsUnauthorized() throws Exception {
		mockMvc.perform(get("/audit/verify"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error").value("Unauthorized"));
	}

	@Test
	void invalidJwtIsUnauthorized() throws Exception {
		mockMvc.perform(get("/audit/verify").header(HttpHeaders.AUTHORIZATION, "Bearer not-valid"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void regulatorCanReadEventsButCannotCreate() throws Exception {
		String token = login("regulator", "Regulator@123");
		mockMvc.perform(get("/audit/events").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isOk());
		mockMvc.perform(get("/audit/export").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isOk())
				.andExpect(header().exists(HttpHeaders.CONTENT_DISPOSITION));
		mockMvc.perform(post("/audit/createEvent")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"eventType":"LOGIN","actorId":"actor-1","resourceType":"SESSION","resourceId":"s-1","payload":"{}"}
						"""))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.error").value("Access Forbidden"));
		mockMvc.perform(get("/audit/verify").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isForbidden());
		mockMvc.perform(put("/audit/checkForRetention").header(HttpHeaders.AUTHORIZATION, "Bearer " + token).param("days", "90"))
				.andExpect(status().isForbidden());
		mockMvc.perform(put("/audit/redact").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.param("id", "1").param("fields", "account"))
				.andExpect(status().isForbidden());
	}

	@Test
	void viewerCannotAccessAuditEndpoints() throws Exception {
		String token = login("viewer", "User@123");
		mockMvc.perform(get("/audit/events").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isForbidden());
		mockMvc.perform(get("/audit/export").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isForbidden());
	}

	@Test
	void adminCanVerifyRetentionAndRedact() throws Exception {
		String token = login("admin", "Admin@123");
		mockMvc.perform(post("/audit/createEvent")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"eventType":"LOGIN","actorId":"actor-1","resourceType":"SESSION","resourceId":"s-2","payload":"{\\"name\\":\\"Alice\\"}"}
						"""))
				.andExpect(status().isCreated());
		mockMvc.perform(get("/audit/verify").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isOk());
		mockMvc.perform(put("/audit/checkForRetention").header(HttpHeaders.AUTHORIZATION, "Bearer " + token).param("days", "90"))
				.andExpect(status().isOk());
		mockMvc.perform(get("/audit/events").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isOk());
	}

	@Test
	void usernameAndUseremailHeadersAreIgnored() throws Exception {
		mockMvc.perform(get("/audit/verify")
				.header("username", "admin")
				.header("useremail", "admin@example.com"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void allowedOriginPreflightIsAccepted() throws Exception {
		mockMvc.perform(options("/audit/export")
				.header(HttpHeaders.ORIGIN, "http://localhost:8080")
				.header("Access-Control-Request-Method", "GET")
				.header("Access-Control-Request-Headers", "Authorization"))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:8080"))
				.andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, "Authorization"))
				.andExpect(header().string(HttpHeaders.ACCESS_CONTROL_MAX_AGE, "3600"))
				.andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS));
	}

	@Test
	void disallowedOriginPreflightIsBlocked() throws Exception {
		mockMvc.perform(options("/audit/export")
				.header(HttpHeaders.ORIGIN, "http://evil.example")
				.header("Access-Control-Request-Method", "GET")
				.header("Access-Control-Request-Headers", "Authorization"))
				.andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
	}

	@Test
	void exportExposesContentDispositionForAllowedOrigin() throws Exception {
		String token = login("regulator", "Regulator@123");
		mockMvc.perform(get("/audit/export")
				.header(HttpHeaders.ORIGIN, "http://localhost:8082")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:8082"))
				.andExpect(header().string(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "Content-Disposition"))
				.andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"Event_Bundle.csv\""));
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
		MvcResult result = mockMvc.perform(post("/audit/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.tokenType").value("Bearer"))
				.andExpect(jsonPath("$.userType").exists())
				.andReturn();
		String json = result.getResponse().getContentAsString();
		int start = json.indexOf("\"accessToken\":\"") + "\"accessToken\":\"".length();
		int end = json.indexOf('"', start);
		return json.substring(start, end);
	}
}
