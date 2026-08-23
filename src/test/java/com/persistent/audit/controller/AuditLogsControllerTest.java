package com.persistent.audit.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import com.persistent.audit.exceptions.AuditExceptionHandler;
import com.persistent.audit.exceptions.UserNotFoundException;
import com.persistent.audit.model.ChainVerificationResult;
import com.persistent.audit.model.EventCreateResponseObject;
import com.persistent.audit.model.RetentionCheckResult;
import com.persistent.audit.service.EventService;
import com.persistent.audit.service.UserService;

@ExtendWith(MockitoExtension.class)
class AuditLogsControllerTest {

	private static final String ADMIN_USERNAME = "admin";
	private static final String ADMIN_EMAIL = "admin@example.com";
	private static final String REGULATOR_USERNAME = "regulator";
	private static final String REGULATOR_EMAIL = "regulator@example.com";
	private static final String USER_USERNAME = "viewer";
	private static final String USER_EMAIL = "viewer@example.com";

	@Mock
	private EventService eventService;

	@Mock
	private UserService userService;

	@InjectMocks
	private AuditLogsController auditLogsController;

	private MockMvc mockMvc;

	@BeforeEach
	void setUp() {
		LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
		validator.afterPropertiesSet();
		mockMvc = MockMvcBuilders.standaloneSetup(auditLogsController)
				.setControllerAdvice(new AuditExceptionHandler())
				.setValidator(validator)
				.build();
		lenient().when(userService.retrieveUserType(any(), any())).thenReturn("ADMIN");
	}

	private MockHttpServletRequestBuilder withAdmin(MockHttpServletRequestBuilder request) {
		return request.header("username", ADMIN_USERNAME).header("useremail", ADMIN_EMAIL);
	}

	private MockHttpServletRequestBuilder withHeaders(
			MockHttpServletRequestBuilder request, String username, String useremail) {
		return request.header("username", username).header("useremail", useremail);
	}

	@Test
	void createEvent_returnsCreated() throws Exception {
		EventCreateResponseObject response = new EventCreateResponseObject(
				1L, "LOGIN", "actor-1", "SESSION", "s-1", "{}", Instant.parse("2026-08-22T10:15:30Z"));
		when(eventService.createEvent(eq("LOGIN"), eq("actor-1"), eq("SESSION"), eq("s-1"), eq("{}")))
				.thenReturn(response);

		mockMvc.perform(withAdmin(post("/audit/createEvent"))
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"eventType":"LOGIN","actorId":"actor-1","resourceType":"SESSION","resourceId":"s-1","payload":"{}"}
						"""))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.id").value(1))
				.andExpect(jsonPath("$.eventType").value("LOGIN"))
				.andExpect(jsonPath("$.hash").doesNotExist())
				.andExpect(jsonPath("$.previousHash").doesNotExist());

		verify(userService).retrieveUserType(ADMIN_EMAIL, ADMIN_USERNAME);
	}

	@Test
	void createEvent_missingMandatoryFieldsReturnsBadRequest() throws Exception {
		mockMvc.perform(withAdmin(post("/audit/createEvent"))
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"eventType":"","actorId":"actor-1","resourceType":"SESSION","resourceId":"s-1","payload":"{}"}
						"""))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.status").value(400))
				.andExpect(jsonPath("$.fields.eventType").exists());
	}

	@Test
	void createEvent_malformedJsonReturnsBadRequest() throws Exception {
		mockMvc.perform(withAdmin(post("/audit/createEvent"))
				.contentType(MediaType.APPLICATION_JSON)
				.content("{not-json"))
				.andExpect(status().isBadRequest());
	}

	@Test
	void getEvents_withoutFiltersReturnsOk() {
		when(eventService.getEvents(isNull(), isNull(), isNull(), isNull(), isNull(), isNull()))
				.thenReturn(new PageImpl<>(List.of()));

		ResponseEntity<Page<EventCreateResponseObject>> response = auditLogsController.getEvents(
				ADMIN_USERNAME, ADMIN_EMAIL, null, null, null, null, null, null);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
		assertThat(response.getBody().getContent()).isEmpty();
	}

	@Test
	void getEvents_withFiltersPassesQueryParams() throws Exception {
		when(eventService.getEvents(eq("LOGIN"), eq("actor-1"), eq("SESSION"), eq("s-1"), any(), any()))
				.thenReturn(new PageImpl<>(List.of()));

		Instant from = Instant.parse("2026-08-01T00:00:00Z");
		Instant to = Instant.parse("2026-08-31T23:59:59Z");
		ResponseEntity<Page<EventCreateResponseObject>> response = auditLogsController.getEvents(
				ADMIN_USERNAME, ADMIN_EMAIL, "LOGIN", "actor-1", "SESSION", "s-1", from, to);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
		verify(eventService).getEvents(eq("LOGIN"), eq("actor-1"), eq("SESSION"), eq("s-1"), eq(from), eq(to));
	}

	@Test
	void getEvents_invalidTimestampReturnsBadRequest() throws Exception {
		mockMvc.perform(withAdmin(get("/audit/events")).param("fromTimestamp", "not-a-date"))
				.andExpect(status().isBadRequest());
	}

	@Test
	void verifyChain_returnsOkWithEmptyResult() throws Exception {
		when(eventService.verifyChain()).thenReturn(new ChainVerificationResult());

		mockMvc.perform(withAdmin(get("/audit/verify")))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.firstInvalidRecordId").doesNotExist())
				.andExpect(jsonPath("$.violationDescription").doesNotExist());
	}

	@Test
	void verifyChain_returnsMismatchDetails() throws Exception {
		when(eventService.verifyChain()).thenReturn(new ChainVerificationResult(4L, "HASH MISMATCH"));

		mockMvc.perform(withAdmin(get("/audit/verify")))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.firstInvalidRecordId").value(4))
				.andExpect(jsonPath("$.violationDescription").value("HASH MISMATCH"));
	}

	@Test
	void checkForRetention_validDaysReturnsOk() throws Exception {
		when(eventService.checkForRetention(90)).thenReturn(new RetentionCheckResult(90, 2));

		mockMvc.perform(withAdmin(put("/audit/checkForRetention")).param("days", "90"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.days").value(90))
				.andExpect(jsonPath("$.archivedCount").value(2));

		verify(eventService).checkForRetention(90);
	}

	@Test
	void checkForRetention_nonIntegerDaysReturnsBadRequest() throws Exception {
		mockMvc.perform(withAdmin(put("/audit/checkForRetention")).param("days", "ninety"))
				.andExpect(status().isBadRequest());

		verify(eventService, never()).checkForRetention(anyInt());
	}

	@Test
	void checkForRetention_missingDaysReturnsBadRequest() throws Exception {
		mockMvc.perform(withAdmin(put("/audit/checkForRetention")))
				.andExpect(status().isBadRequest());

		verify(eventService, never()).checkForRetention(anyInt());
	}

	@Test
	void checkForRetention_nonPositiveDaysReturnsBadRequest() throws Exception {
		mockMvc.perform(withAdmin(put("/audit/checkForRetention")).param("days", "0"))
				.andExpect(status().isBadRequest());
		mockMvc.perform(withAdmin(put("/audit/checkForRetention")).param("days", "-5"))
				.andExpect(status().isBadRequest());

		verify(eventService, never()).checkForRetention(anyInt());
	}

	@Test
	void redact_returnsOkEvent() throws Exception {
		EventCreateResponseObject redacted = new EventCreateResponseObject(
				8L, "LOGIN", "actor-1", "SESSION", "s-8",
				"{\"account\":null,\"name\":\"Alice\"}", Instant.parse("2026-08-22T10:15:30Z"));
		when(eventService.redactFieldsFromPayload(8L, "account")).thenReturn(redacted);

		mockMvc.perform(withAdmin(put("/audit/redact")).param("id", "8").param("fields", "account"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.id").value(8))
				.andExpect(jsonPath("$.payload").value("{\"account\":null,\"name\":\"Alice\"}"));

		verify(eventService).redactFieldsFromPayload(8L, "account");
	}

	@Test
	void redact_missingIdReturnsBadRequest() throws Exception {
		mockMvc.perform(withAdmin(put("/audit/redact")).param("fields", "account"))
				.andExpect(status().isBadRequest());
	}

	@Test
	void redact_nonIntegerIdReturnsBadRequest() throws Exception {
		mockMvc.perform(withAdmin(put("/audit/redact")).param("id", "abc").param("fields", "account"))
				.andExpect(status().isBadRequest());
	}

	@Test
	void redact_nonPositiveIdReturnsBadRequest() throws Exception {
		mockMvc.perform(withAdmin(put("/audit/redact")).param("id", "0").param("fields", "account"))
				.andExpect(status().isBadRequest());
	}

	@Test
	void redact_blankFieldsReturnsBadRequest() throws Exception {
		mockMvc.perform(withAdmin(put("/audit/redact")).param("id", "1").param("fields", "   "))
				.andExpect(status().isBadRequest());
	}

	@Test
	void redact_unknownEventReturnsNotFound() throws Exception {
		when(eventService.redactFieldsFromPayload(44L, "account"))
				.thenThrow(new NoSuchElementException("Event not found for id=44"));

		mockMvc.perform(withAdmin(put("/audit/redact")).param("id", "44").param("fields", "account"))
				.andExpect(status().isNotFound());
	}

	@Test
	void redact_unknownPayloadFieldReturnsBadRequest() throws Exception {
		when(eventService.redactFieldsFromPayload(1L, "missing"))
				.thenThrow(new IllegalArgumentException("payload does not contain field: missing"));

		mockMvc.perform(withAdmin(put("/audit/redact")).param("id", "1").param("fields", "missing"))
				.andExpect(status().isBadRequest());
	}

	@Test
	void exportBundle_returnsCsvAttachment() throws Exception {
		byte[] csv = "id,eventType\n1,LOGIN\n".getBytes();
		when(eventService.exportBundle("res-1", "actor-1")).thenReturn(csv);

		mockMvc.perform(withAdmin(get("/audit/export")).param("resourceId", "res-1").param("actorId", "actor-1"))
				.andExpect(status().isOk())
				.andExpect(header().string("Content-Disposition", "attachment; filename=\"Event_Bundle.csv\""))
				.andExpect(content().contentType("text/csv"))
				.andExpect(content().bytes(csv));

		verify(eventService).exportBundle("res-1", "actor-1");
	}

	@Test
	void exportBundle_optionalFiltersArePassedThrough() throws Exception {
		when(eventService.exportBundle(null, null)).thenReturn("id\n".getBytes());

		mockMvc.perform(withAdmin(get("/audit/export")))
				.andExpect(status().isOk());

		verify(eventService).exportBundle(null, null);
	}

	@Test
	void missingUsernameHeaderReturnsBadRequest() throws Exception {
		mockMvc.perform(get("/audit/verify").header("useremail", ADMIN_EMAIL))
				.andExpect(status().isBadRequest());
	}

	@Test
	void missingUseremailHeaderReturnsBadRequest() throws Exception {
		mockMvc.perform(get("/audit/verify").header("username", ADMIN_USERNAME))
				.andExpect(status().isBadRequest());
	}

	@Test
	void blankHeadersReturnBadRequest() throws Exception {
		mockMvc.perform(get("/audit/verify").header("username", "  ").header("useremail", "  "))
				.andExpect(status().isBadRequest());
	}

	@Test
	void unknownUserReturnsUnauthorized() throws Exception {
		when(userService.retrieveUserType(ADMIN_EMAIL, ADMIN_USERNAME))
				.thenThrow(new UserNotFoundException("User not found for the given username and useremail"));

		mockMvc.perform(withAdmin(get("/audit/verify")))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.status").value(401));
	}

	@Test
	void userTypeForbiddenOnAdminEndpoints() throws Exception {
		when(userService.retrieveUserType(USER_EMAIL, USER_USERNAME)).thenReturn("USER");

		mockMvc.perform(withHeaders(post("/audit/createEvent"), USER_USERNAME, USER_EMAIL)
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"eventType":"LOGIN","actorId":"actor-1","resourceType":"SESSION","resourceId":"s-1","payload":"{}"}
						"""))
				.andExpect(status().isForbidden());
		mockMvc.perform(withHeaders(get("/audit/verify"), USER_USERNAME, USER_EMAIL))
				.andExpect(status().isForbidden());
		mockMvc.perform(withHeaders(put("/audit/checkForRetention"), USER_USERNAME, USER_EMAIL).param("days", "90"))
				.andExpect(status().isForbidden());
		mockMvc.perform(withHeaders(put("/audit/redact"), USER_USERNAME, USER_EMAIL)
				.param("id", "1").param("fields", "account"))
				.andExpect(status().isForbidden());
		mockMvc.perform(withHeaders(get("/audit/events"), USER_USERNAME, USER_EMAIL))
				.andExpect(status().isForbidden());
		mockMvc.perform(withHeaders(get("/audit/export"), USER_USERNAME, USER_EMAIL))
				.andExpect(status().isForbidden());

		verify(eventService, never()).createEvent(any(), any(), any(), any(), any());
		verify(eventService, never()).verifyChain();
		verify(eventService, never()).checkForRetention(anyInt());
		verify(eventService, never()).exportBundle(any(), any());
	}

	@Test
	void regulatorAllowedOnGetEventsAndExport() throws Exception {
		when(userService.retrieveUserType(REGULATOR_EMAIL, REGULATOR_USERNAME)).thenReturn("REGULATOR");
		when(eventService.getEvents(isNull(), isNull(), isNull(), isNull(), isNull(), isNull()))
				.thenReturn(new PageImpl<>(List.of()));
		when(eventService.exportBundle(null, null)).thenReturn("id\n".getBytes());

		ResponseEntity<Page<EventCreateResponseObject>> eventsResponse = auditLogsController.getEvents(
				REGULATOR_USERNAME, REGULATOR_EMAIL, null, null, null, null, null, null);
		assertThat(eventsResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

		mockMvc.perform(withHeaders(get("/audit/export"), REGULATOR_USERNAME, REGULATOR_EMAIL))
				.andExpect(status().isOk());
	}

	@Test
	void regulatorForbiddenOnAdminOnlyEndpoints() throws Exception {
		when(userService.retrieveUserType(REGULATOR_EMAIL, REGULATOR_USERNAME)).thenReturn("REGULATOR");

		mockMvc.perform(withHeaders(post("/audit/createEvent"), REGULATOR_USERNAME, REGULATOR_EMAIL)
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"eventType":"LOGIN","actorId":"actor-1","resourceType":"SESSION","resourceId":"s-1","payload":"{}"}
						"""))
				.andExpect(status().isForbidden());
		mockMvc.perform(withHeaders(get("/audit/verify"), REGULATOR_USERNAME, REGULATOR_EMAIL))
				.andExpect(status().isForbidden());
		mockMvc.perform(withHeaders(put("/audit/checkForRetention"), REGULATOR_USERNAME, REGULATOR_EMAIL)
				.param("days", "90"))
				.andExpect(status().isForbidden());
		mockMvc.perform(withHeaders(put("/audit/redact"), REGULATOR_USERNAME, REGULATOR_EMAIL)
				.param("id", "1").param("fields", "account"))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.error").value("Access Forbidden"));

		verify(eventService, never()).createEvent(any(), any(), any(), any(), any());
		verify(eventService, never()).verifyChain();
		verify(eventService, never()).checkForRetention(anyInt());
		verify(eventService, never()).redactFieldsFromPayload(any(), any());
	}
}
