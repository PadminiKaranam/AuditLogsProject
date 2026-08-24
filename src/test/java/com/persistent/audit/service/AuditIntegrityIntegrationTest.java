package com.persistent.audit.service;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.persistent.audit.model.User;
import com.persistent.audit.repository.UserRepository;

@SpringBootTest
@AutoConfigureMockMvc
class AuditIntegrityIntegrationTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@BeforeEach
	void ensureUsers() {
		ensureUser("admin", "ADMIN", "admin@example.com", "Admin@123");
	}

	@Test
	void directSqlTamperIsDetectedByVerify() throws Exception {
		String adminToken = login("admin", "Admin@123");
		MvcResult created = mockMvc.perform(post("/audit/createEvent")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"eventType\":\"LOGIN\",\"actorId\":\"actor-sql\",\"resourceType\":\"SESSION\",\"resourceId\":\"s-sql\",\"payload\":\"{\\\"name\\\":\\\"Alice\\\"}\"}"))
				.andExpect(status().isCreated())
				.andReturn();
		String body = created.getResponse().getContentAsString();
		long id = Long.parseLong(body.replaceAll(".*\"id\":(\\d+).*", "$1"));

		mockMvc.perform(get("/audit/verify").header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.firstInvalidRecordId").doesNotExist());

		jdbcTemplate.update("UPDATE EVENT SET ACTOR_ID = 'tampered-actor' WHERE ID = ?", id);

		mockMvc.perform(get("/audit/verify").header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.firstInvalidRecordId").value(id))
				.andExpect(jsonPath("$.violationDescription").value("EVENT HASH MISMATCH"));
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
