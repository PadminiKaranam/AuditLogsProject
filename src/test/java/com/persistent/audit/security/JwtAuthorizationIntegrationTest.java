package com.persistent.audit.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
class JwtAuthorizationIntegrationTest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void loginSuccessAndAdminCanCreateEvent() throws Exception {
		String token = login("admin", "Admin@123");
		mockMvc.perform(post("/audit/createEvent")
				.header("Authorization", "Bearer " + token)
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
	void missingBearerTokenIsUnauthorized() throws Exception {
		mockMvc.perform(get("/audit/verify"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error").value("Unauthorized"));
	}

	@Test
	void invalidJwtIsUnauthorized() throws Exception {
		mockMvc.perform(get("/audit/verify").header("Authorization", "Bearer not-valid"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void regulatorCanReadEventsButCannotCreate() throws Exception {
		String token = login("regulator", "Regulator@123");
		mockMvc.perform(get("/audit/events").header("Authorization", "Bearer " + token))
				.andExpect(status().isOk());
		mockMvc.perform(get("/audit/export").header("Authorization", "Bearer " + token))
				.andExpect(status().isOk());
		mockMvc.perform(post("/audit/createEvent")
				.header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"eventType":"LOGIN","actorId":"actor-1","resourceType":"SESSION","resourceId":"s-1","payload":"{}"}
						"""))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.error").value("Access Forbidden"));
		mockMvc.perform(get("/audit/verify").header("Authorization", "Bearer " + token))
				.andExpect(status().isForbidden());
		mockMvc.perform(put("/audit/checkForRetention").header("Authorization", "Bearer " + token).param("days", "90"))
				.andExpect(status().isForbidden());
		mockMvc.perform(put("/audit/redact").header("Authorization", "Bearer " + token)
				.param("id", "1").param("fields", "account"))
				.andExpect(status().isForbidden());
	}

	@Test
	void viewerCannotAccessAuditEndpoints() throws Exception {
		String token = login("viewer", "User@123");
		mockMvc.perform(get("/audit/events").header("Authorization", "Bearer " + token))
				.andExpect(status().isForbidden());
		mockMvc.perform(get("/audit/export").header("Authorization", "Bearer " + token))
				.andExpect(status().isForbidden());
	}

	@Test
	void adminCanVerifyRetentionAndRedact() throws Exception {
		String token = login("admin", "Admin@123");
		mockMvc.perform(post("/audit/createEvent")
				.header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"eventType":"LOGIN","actorId":"actor-1","resourceType":"SESSION","resourceId":"s-2","payload":"{\\"name\\":\\"Alice\\"}"}
						"""))
				.andExpect(status().isCreated());
		mockMvc.perform(get("/audit/verify").header("Authorization", "Bearer " + token))
				.andExpect(status().isOk());
		mockMvc.perform(put("/audit/checkForRetention").header("Authorization", "Bearer " + token).param("days", "90"))
				.andExpect(status().isOk());
		mockMvc.perform(get("/audit/events").header("Authorization", "Bearer " + token))
				.andExpect(status().isOk());
	}

	@Test
	void usernameAndUseremailHeadersAreIgnored() throws Exception {
		mockMvc.perform(get("/audit/verify")
				.header("username", "admin")
				.header("useremail", "admin@example.com"))
				.andExpect(status().isUnauthorized());
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
