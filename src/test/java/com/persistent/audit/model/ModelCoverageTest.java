package com.persistent.audit.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.Test;

class ModelCoverageTest {

	@Test
	void eventPrePersistAssignsTimestampAndStatus() {
		Event event = new Event("LOGIN", "a", "SESSION", "s", "{}", "h", null);
		assertThat(event.getEventType()).isEqualTo("LOGIN");
		assertThat(event.getPayload()).isEqualTo("{}");
		assertThat(event.getHash()).isEqualTo("h");
		event.setTimestamp(null);
		event.setStatus(null);
		event.assignServerTimestamp();
		assertThat(event.getTimestamp()).isNotNull();
		assertThat(event.getStatus()).isEqualTo(EventStatus.ACTIVE);

		Instant existing = Instant.parse("2026-08-22T10:15:30Z");
		event.setTimestamp(existing);
		event.setStatus(EventStatus.ARCHIVED);
		event.assignServerTimestamp();
		assertThat(event.getTimestamp()).isEqualTo(existing);
		assertThat(event.getStatus()).isEqualTo(EventStatus.ARCHIVED);
	}

	@Test
	void eventCreateResponseObjectFromCopiesVisibleFields() {
		Event event = new Event();
		event.setId(9L);
		event.setEventType("LOGIN");
		event.setActorId("actor");
		event.setResourceType("SESSION");
		event.setResourceId("s-9");
		event.setPayload("{}");
		event.setTimestamp(Instant.parse("2026-08-22T10:15:30Z"));
		EventCreateResponseObject dto = EventCreateResponseObject.from(event);
		assertThat(dto.getId()).isEqualTo(9L);
		assertThat(dto.getPayload()).isEqualTo("{}");
	}

	@Test
	void loginAndBundleDtosHoldValues() {
		LoginRequest request = new LoginRequest("admin", "secret");
		assertThat(request.getUsername()).isEqualTo("admin");
		LoginResponse response = new LoginResponse("t", "Bearer", 1L, "admin", "a@b.c", "ADMIN");
		assertThat(response.getTokenType()).isEqualTo("Bearer");
		BundleExportStructureResponse row = new BundleExportStructureResponse(
				1L, "LOGIN", "a", "SESSION", "s", "{}", Instant.parse("2026-08-22T10:15:30Z"), "meta");
		assertThat(row.getChainMetadata()).isEqualTo("meta");
		assertThat(EventStatus.values()).contains(EventStatus.ACTIVE, EventStatus.ARCHIVED);
	}
}
