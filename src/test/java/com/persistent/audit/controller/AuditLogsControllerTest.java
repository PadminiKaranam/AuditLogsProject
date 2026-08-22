package com.persistent.audit.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;

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
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import com.persistent.audit.model.ChainVerificationResult;
import com.persistent.audit.model.EventCreateResponseObject;
import com.persistent.audit.model.RetentionCheckResult;
import com.persistent.audit.service.EventService;

@ExtendWith(MockitoExtension.class)
class AuditLogsControllerTest {

	@Mock
	private EventService eventService;

	@InjectMocks
	private AuditLogsController auditLogsController;

	private MockMvc mockMvc;

	@BeforeEach
	void setUp() {
		LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
		validator.afterPropertiesSet();
		mockMvc = MockMvcBuilders.standaloneSetup(auditLogsController)
				.setValidator(validator)
				.build();
	}

	@Test
	void createEvent_returnsCreated() throws Exception {
		EventCreateResponseObject response = new EventCreateResponseObject(
				1L, "LOGIN", "actor-1", "SESSION", "s-1", "{}", Instant.parse("2026-08-22T10:15:30Z"));
		when(eventService.createEvent(eq("LOGIN"), eq("actor-1"), eq("SESSION"), eq("s-1"), eq("{}")))
				.thenReturn(response);

		mockMvc.perform(post("/audit/createEvent")
				.contentType(MediaType.APPLICATION_JSON)
				.content("""
						{"eventType":"LOGIN","actorId":"actor-1","resourceType":"SESSION","resourceId":"s-1","payload":"{}"}
						"""))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.id").value(1))
				.andExpect(jsonPath("$.eventType").value("LOGIN"))
				.andExpect(jsonPath("$.hash").doesNotExist())
				.andExpect(jsonPath("$.previousHash").doesNotExist());
	}

	@Test
	void createEvent_missingMandatoryFieldsReturnsBadRequest() throws Exception {
		mockMvc.perform(post("/audit/createEvent")
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
		mockMvc.perform(post("/audit/createEvent")
				.contentType(MediaType.APPLICATION_JSON)
				.content("{not-json"))
				.andExpect(status().isBadRequest());
	}

	@Test
	void getEvents_withoutFiltersReturnsOk() {
		when(eventService.getEvents(isNull(), isNull(), isNull(), isNull(), isNull(), isNull()))
				.thenReturn(new PageImpl<>(List.of()));

		ResponseEntity<Page<EventCreateResponseObject>> response = auditLogsController.getEvents(
				null, null, null, null, null, null);

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
				"LOGIN", "actor-1", "SESSION", "s-1", from, to);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
		verify(eventService).getEvents(eq("LOGIN"), eq("actor-1"), eq("SESSION"), eq("s-1"), eq(from), eq(to));
	}

	@Test
	void getEvents_invalidTimestampReturnsBadRequest() throws Exception {
		mockMvc.perform(get("/audit/events").param("fromTimestamp", "not-a-date"))
				.andExpect(status().isBadRequest());
	}

	@Test
	void verifyChain_returnsOkWithEmptyResult() throws Exception {
		when(eventService.verifyChain()).thenReturn(new ChainVerificationResult());

		mockMvc.perform(get("/audit/verify"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.firstInvalidRecordId").doesNotExist())
				.andExpect(jsonPath("$.violationDescription").doesNotExist());
	}

	@Test
	void verifyChain_returnsMismatchDetails() throws Exception {
		when(eventService.verifyChain()).thenReturn(new ChainVerificationResult(4L, "HASH MISMATCH"));

		mockMvc.perform(get("/audit/verify"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.firstInvalidRecordId").value(4))
				.andExpect(jsonPath("$.violationDescription").value("HASH MISMATCH"));
	}

	@Test
	void checkForRetention_validDaysReturnsOk() throws Exception {
		when(eventService.checkForRetention(90)).thenReturn(new RetentionCheckResult(90, 2));

		mockMvc.perform(put("/audit/checkForRetention").param("days", "90"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.days").value(90))
				.andExpect(jsonPath("$.archivedCount").value(2));

		verify(eventService).checkForRetention(90);
	}

	@Test
	void checkForRetention_nonIntegerDaysReturnsBadRequest() throws Exception {
		mockMvc.perform(put("/audit/checkForRetention").param("days", "ninety"))
				.andExpect(status().isBadRequest());

		verify(eventService, never()).checkForRetention(anyInt());
	}

	@Test
	void checkForRetention_missingDaysReturnsBadRequest() throws Exception {
		mockMvc.perform(put("/audit/checkForRetention"))
				.andExpect(status().isBadRequest());

		verify(eventService, never()).checkForRetention(anyInt());
	}

	@Test
	void checkForRetention_nonPositiveDaysReturnsBadRequest() throws Exception {
		mockMvc.perform(put("/audit/checkForRetention").param("days", "0"))
				.andExpect(status().isBadRequest());
		mockMvc.perform(put("/audit/checkForRetention").param("days", "-5"))
				.andExpect(status().isBadRequest());

		verify(eventService, never()).checkForRetention(anyInt());
	}
}
