package com.persistent.audit.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import com.persistent.audit.crypto.PayloadMerkleHasher;
import com.persistent.audit.model.ChainVerificationResult;
import com.persistent.audit.model.Event;
import com.persistent.audit.model.EventCreateResponseObject;
import com.persistent.audit.model.EventStatus;
import com.persistent.audit.model.RetentionCheckResult;
import com.persistent.audit.repository.EventRepository;
import com.persistent.audit.util.PaginationUtils;

@ExtendWith(MockitoExtension.class)
class EventServiceTest {

	@Mock
	private EventRepository eventRepository;

	@InjectMocks
	private EventService eventService;

	private Instant now;

	@BeforeEach
	void setUp() {
		now = Instant.parse("2026-08-22T10:15:30Z");
	}

	@Test
	void createEvent_firstRecordHasNullPreviousHash() {
		when(eventRepository.findTopByOrderByIdDesc()).thenReturn(Optional.empty());
		when(eventRepository.save(any(Event.class))).thenAnswer(invocation -> {
			Event event = invocation.getArgument(0);
			event.setId(1L);
			return event;
		});

		EventCreateResponseObject result = eventService.createEvent("LOGIN", "actor-1", "SESSION", "s-1", "{}");

		ArgumentCaptor<Event> captor = ArgumentCaptor.forClass(Event.class);
		verify(eventRepository).save(captor.capture());
		Event saved = captor.getValue();
		assertThat(saved.getPreviousHash()).isNull();
		assertThat(saved.getHash()).isNotBlank();
		assertThat(saved.getStatus()).isEqualTo(EventStatus.ACTIVE);
		assertThat(result.getId()).isEqualTo(1L);
		assertThat(result.getEventType()).isEqualTo("LOGIN");
	}

	@Test
	void createEvent_linksPreviousHashFromLatestStoredHash() {
		Event previous = committedEvent(1L, "{\"name\":\"Alice\"}", null);
		when(eventRepository.findTopByOrderByIdDesc()).thenReturn(Optional.of(previous));
		when(eventRepository.save(any(Event.class))).thenAnswer(invocation -> {
			Event event = invocation.getArgument(0);
			event.setId(2L);
			return event;
		});

		eventService.createEvent("LOGOUT", "actor-1", "SESSION", "s-1", "{}");

		ArgumentCaptor<Event> captor = ArgumentCaptor.forClass(Event.class);
		verify(eventRepository).save(captor.capture());
		assertThat(captor.getValue().getPreviousHash()).isEqualTo(previous.getHash());
		assertThat(captor.getValue().getHash()).isNotEqualTo(previous.getHash());
	}

	@Test
	void createEvent_blankPayloadIsStoredAsSubmitted() {
		when(eventRepository.findTopByOrderByIdDesc()).thenReturn(Optional.empty());
		when(eventRepository.save(any(Event.class))).thenAnswer(invocation -> invocation.getArgument(0));

		eventService.createEvent("LOGIN", "actor-1", "SESSION", "s-1", "  ");

		ArgumentCaptor<Event> captor = ArgumentCaptor.forClass(Event.class);
		verify(eventRepository).save(captor.capture());
		assertThat(captor.getValue().getPayload()).isEqualTo("  ");
		assertThat(captor.getValue().getHash()).hasSize(64);
	}

	@Test
	void createEvent_nullPayloadIsStoredAsNull() {
		when(eventRepository.findTopByOrderByIdDesc()).thenReturn(Optional.empty());
		when(eventRepository.save(any(Event.class))).thenAnswer(invocation -> invocation.getArgument(0));

		eventService.createEvent("LOGIN", "actor-1", "SESSION", "s-1", null);

		ArgumentCaptor<Event> captor = ArgumentCaptor.forClass(Event.class);
		verify(eventRepository).save(captor.capture());
		assertThat(captor.getValue().getPayload()).isNull();
		assertThat(captor.getValue().getHash()).hasSize(64);
	}

	@Test
	void createEvent_responseExcludesHashFields() {
		when(eventRepository.findTopByOrderByIdDesc()).thenReturn(Optional.empty());
		when(eventRepository.save(any(Event.class))).thenAnswer(invocation -> {
			Event event = invocation.getArgument(0);
			event.setId(9L);
			return event;
		});

		EventCreateResponseObject result = eventService.createEvent("LOGIN", "actor-1", "SESSION", "s-1", "{}");

		assertThat(result.getId()).isEqualTo(9L);
		assertThat(result.getPayload()).isEqualTo("{}");
		assertThat(result).hasNoNullFieldsOrPropertiesExcept();
	}

	@Test
	void createEvent_computesMerkleEventHashFromPayloadRootNotRawJson() {
		when(eventRepository.findTopByOrderByIdDesc()).thenReturn(Optional.empty());
		when(eventRepository.save(any(Event.class))).thenAnswer(invocation -> invocation.getArgument(0));
		String payload = "{\"account\":\"12345\",\"name\":\"Alice\"}";

		eventService.createEvent("LOGIN", "actor-1", "SESSION", "s-1", payload);

		ArgumentCaptor<Event> captor = ArgumentCaptor.forClass(Event.class);
		verify(eventRepository).save(captor.capture());
		Event saved = captor.getValue();
		assertThat(saved.getPayload()).isEqualTo(payload);
		var payloadNode = PayloadMerkleHasher.parseObject(saved.getPayload());
		assertThat(payloadNode.has(PayloadMerkleHasher.SALTS_KEY)).isFalse();
		assertThat(payloadNode.has(PayloadMerkleHasher.LEAVES_KEY)).isFalse();
		assertThat(payloadNode.get("name").asString()).isEqualTo("Alice");
		assertThat(saved.getHash()).hasSize(64);
		assertThat(saved.getHash()).isNotEqualTo(PayloadMerkleHasher.computeEventHash(
				"LOGIN", "actor-1", "SESSION", "s-1", payload, saved.getTimestamp(), null));
	}

	@Test
	void createEvent_rejectsInvalidPayloadJson() {
		when(eventRepository.findTopByOrderByIdDesc()).thenReturn(Optional.empty());

		assertThatThrownBy(() -> eventService.createEvent("LOGIN", "actor-1", "SESSION", "s-1", "{not-json"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("JSON");
		verify(eventRepository, never()).save(any(Event.class));
	}

	@Test
	void createEvent_rejectsJsonArrayPayload() {
		when(eventRepository.findTopByOrderByIdDesc()).thenReturn(Optional.empty());

		assertThatThrownBy(() -> eventService.createEvent("LOGIN", "actor-1", "SESSION", "s-1", "[1,2]"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("JSON object");
	}

	@Test
	void redactFieldsFromPayload_nullsValueKeepsSaltLeafHashAndEventHash() {
		Event stored = committedEvent(7L, "{\"name\":\"Alice\",\"account\":\"12345\"}", null);
		String originalHash = stored.getHash();
		String accountLeaf = PayloadMerkleHasher.nestedStringMap(
				PayloadMerkleHasher.parseObject(stored.getPayload()), PayloadMerkleHasher.LEAVES_KEY).get("account");
		when(eventRepository.findById(7L)).thenReturn(Optional.of(stored));
		when(eventRepository.save(any(Event.class))).thenAnswer(invocation -> invocation.getArgument(0));
		String rootBeforeRedact = PayloadMerkleHasher.payloadRootFromPayload(stored.getPayload());

		EventCreateResponseObject result = eventService.redactFieldsFromPayload(7L, "account");

		var payload = PayloadMerkleHasher.parseObject(result.getPayload());
		assertThat(payload.get("account").isNull()).isTrue();
		assertThat(payload.get("name").asString()).isEqualTo("Alice");
		assertThat(PayloadMerkleHasher.nestedStringMap(payload, PayloadMerkleHasher.SALTS_KEY)).containsKey("account");
		assertThat(PayloadMerkleHasher.nestedStringMap(payload, PayloadMerkleHasher.SALTS_KEY)).containsKey("name");
		assertThat(PayloadMerkleHasher.nestedStringMap(payload, PayloadMerkleHasher.LEAVES_KEY).get("account"))
				.isEqualTo(accountLeaf);
		assertThat(stored.getHash()).isEqualTo(originalHash);
		assertThat(PayloadMerkleHasher.payloadRootFromPayload(result.getPayload())).isEqualTo(rootBeforeRedact);
		assertThat(stored.getPreviousHash()).isNull();
	}

	@Test
	void redactFieldsFromPayload_multipleKeysAndWhitespace() {
		Event stored = committedEvent(3L, "{\"name\":\"Alice\",\"account\":\"12345\",\"ssn\":\"999\"}", "prev");
		when(eventRepository.findById(3L)).thenReturn(Optional.of(stored));
		when(eventRepository.save(any(Event.class))).thenAnswer(invocation -> invocation.getArgument(0));

		EventCreateResponseObject result = eventService.redactFieldsFromPayload(3L, " account , ssn ");

		assertThat(PayloadMerkleHasher.parseObject(result.getPayload()).get("account").isNull()).isTrue();
		assertThat(PayloadMerkleHasher.parseObject(result.getPayload()).get("ssn").isNull()).isTrue();
		assertThat(PayloadMerkleHasher.parseObject(result.getPayload()).get("name").asString()).isEqualTo("Alice");
		assertThat(stored.getPreviousHash()).isEqualTo("prev");
	}

	@Test
	void redactFieldsFromPayload_missingEventThrows() {
		when(eventRepository.findById(99L)).thenReturn(Optional.empty());

		assertThatThrownBy(() -> eventService.redactFieldsFromPayload(99L, "account"))
				.isInstanceOf(NoSuchElementException.class);
	}

	@Test
	void redactFieldsFromPayload_missingPayloadKeyThrows() {
		Event stored = committedEvent(1L, "{\"name\":\"Alice\"}", null);
		when(eventRepository.findById(1L)).thenReturn(Optional.of(stored));

		assertThatThrownBy(() -> eventService.redactFieldsFromPayload(1L, "account"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("account");
		verify(eventRepository, never()).save(any(Event.class));
	}

	@Test
	void redactFieldsFromPayload_blankFieldsThrows() {
		assertThatThrownBy(() -> eventService.redactFieldsFromPayload(1L, " , , "))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> eventService.redactFieldsFromPayload(null, "account"))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void redactFieldsFromPayload_doesNotBreakChainVerification() {
		Event first = committedEvent(1L, "{\"name\":\"Alice\",\"account\":\"12345\"}", null);
		Event second = committedEvent(2L, "{\"name\":\"Bob\"}", first.getHash());
		when(eventRepository.findById(1L)).thenReturn(Optional.of(first));
		when(eventRepository.save(any(Event.class))).thenAnswer(invocation -> invocation.getArgument(0));
		when(eventRepository.findAll(any(Sort.class))).thenReturn(List.of(first, second));

		assertThat(eventService.verifyChain().getFirstInvalidRecordId()).isNull();
		eventService.redactFieldsFromPayload(1L, "account");
		assertThat(first.getHash()).isNotBlank();
		assertThat(second.getPreviousHash()).isEqualTo(first.getHash());
		assertThat(eventService.verifyChain().getFirstInvalidRecordId()).isNull();
		assertThat(eventService.verifyChain().getViolationDescription()).isNull();
	}

	@Test
	void exportBundle_writesCsvWithChainMetadataForMatchingEvents() {
		Event first = event(1L, "h1", null);
		first.setActorId("actor-1");
		first.setResourceId("res-1");
		first.setPayload("{\"name\":\"Alice\"}");
		Event second = event(2L, "h2", "h1");
		second.setActorId("actor-1");
		second.setResourceId("res-1");
		second.setPayload("{\"name\":\"Bob, Jr\"}");
		when(eventRepository.findForExport("actor-1", "res-1")).thenReturn(List.of(first, second));

		byte[] csvBytes = eventService.exportBundle("res-1", "actor-1");
		String csv = new String(csvBytes, java.nio.charset.StandardCharsets.UTF_8);

		assertThat(csv).startsWith("id,eventType,actorId,resourceType,resourceId,payload,timestamp,chainMetadata\n");
		assertThat(csv).contains("1,LOGIN,actor-1,SESSION,res-1");
		assertThat(csv).contains("\"{\"").contains("Bob, Jr");
		assertThat(csv).contains(PayloadMerkleHasher.sha256("h1"));
		assertThat(csv).contains(PayloadMerkleHasher.sha256("h2h1"));
		verify(eventRepository).findForExport("actor-1", "res-1");
	}

	@Test
	void exportBundle_blankFiltersExportAllSequentialEvents() {
		when(eventRepository.findForExport(null, null)).thenReturn(List.of());

		byte[] csvBytes = eventService.exportBundle("  ", "");
		String csv = new String(csvBytes, java.nio.charset.StandardCharsets.UTF_8);

		assertThat(csv).isEqualTo("id,eventType,actorId,resourceType,resourceId,payload,timestamp,chainMetadata\n");
		verify(eventRepository).findForExport(null, null);
	}

	@Test
	void exportBundle_filtersByActorIdOnly() {
		Event event = event(5L, "h5", "h4");
		event.setActorId("actor-9");
		when(eventRepository.findForExport("actor-9", null)).thenReturn(List.of(event));

		byte[] csvBytes = eventService.exportBundle(null, "actor-9");
		String csv = new String(csvBytes, java.nio.charset.StandardCharsets.UTF_8);

		assertThat(csv).contains("5,LOGIN,actor-9");
		assertThat(csv).contains(PayloadMerkleHasher.sha256("h5h4"));
		verify(eventRepository).findForExport("actor-9", null);
	}

	@Test
	void getEvents_withoutFiltersUsesFindAllAndPageSizeTen() {
		List<Event> pageContent = events(1, 10);
		when(eventRepository.findAll(any(Pageable.class)))
				.thenReturn(new PageImpl<>(pageContent, PaginationUtils.pageRequest(0), 15));

		Page<EventCreateResponseObject> result = eventService.getEvents(null, null, null, null, null, null);

		ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
		verify(eventRepository).findAll(pageableCaptor.capture());
		verify(eventRepository, never()).findEvents(any(), any(), any(), any(), any(), any(), any());
		assertThat(pageableCaptor.getValue().getPageSize()).isEqualTo(10);
		assertThat(pageableCaptor.getValue().getPageNumber()).isEqualTo(0);
		assertThat(result.getContent()).hasSize(10);
		assertThat(result.getTotalElements()).isEqualTo(15);
		assertThat(result.getTotalPages()).isEqualTo(2);
	}

	@Test
	void getEvents_moreThanTenRecords_secondPageHasRemainder() {
		List<Event> secondPage = events(11, 15);
		when(eventRepository.findAll(any(Pageable.class)))
				.thenReturn(new PageImpl<>(secondPage, PaginationUtils.pageRequest(1), 15));

		Page<EventCreateResponseObject> result = eventService.getEvents(null, null, null, null, null, null, 1);

		ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
		verify(eventRepository).findAll(pageableCaptor.capture());
		assertThat(pageableCaptor.getValue().getPageNumber()).isEqualTo(1);
		assertThat(pageableCaptor.getValue().getPageSize()).isEqualTo(10);
		assertThat(result.getContent()).hasSize(5);
		assertThat(result.getTotalElements()).isEqualTo(15);
		assertThat(result.hasNext()).isFalse();
		assertThat(result.hasPrevious()).isTrue();
	}

	@Test
	void getEvents_negativePageIsTreatedAsZero() {
		when(eventRepository.findAll(any(Pageable.class)))
				.thenReturn(new PageImpl<>(List.of(), PaginationUtils.pageRequest(0), 0));

		eventService.getEvents(null, null, null, null, null, null, -3);

		ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
		verify(eventRepository).findAll(pageableCaptor.capture());
		assertThat(pageableCaptor.getValue().getPageNumber()).isEqualTo(0);
	}

	@Test
	void getEvents_blankFiltersAreTreatedAsNoFilters() {
		when(eventRepository.findAll(any(Pageable.class)))
				.thenReturn(new PageImpl<>(List.of(), PaginationUtils.pageRequest(), 0));

		eventService.getEvents("  ", "", null, " ", null, null);

		verify(eventRepository).findAll(any(Pageable.class));
		verify(eventRepository, never()).findEvents(any(), any(), any(), any(), any(), any(), any());
	}

	@Test
	void getEvents_withFiltersUsesFindEventsAndConvertsBlanksToNull() {
		when(eventRepository.findEvents(eq("LOGIN"), isNull(), eq("SESSION"), isNull(), isNull(), isNull(),
				any(Pageable.class)))
				.thenReturn(new PageImpl<>(List.of(event(1L, "h1", null))));

		Page<EventCreateResponseObject> result = eventService.getEvents("LOGIN", "  ", "SESSION", "", null, null);

		verify(eventRepository).findEvents(eq("LOGIN"), isNull(), eq("SESSION"), isNull(), isNull(), isNull(),
				any(Pageable.class));
		assertThat(result.getContent()).hasSize(1);
		assertThat(result.getContent().get(0).getEventType()).isEqualTo("LOGIN");
	}

	@Test
	void getEvents_timestampRangeUsesFindEvents() {
		Instant from = Instant.parse("2026-08-01T00:00:00Z");
		Instant to = Instant.parse("2026-08-31T23:59:59Z");
		when(eventRepository.findEvents(isNull(), isNull(), isNull(), isNull(), eq(from), eq(to), any(Pageable.class)))
				.thenReturn(new PageImpl<>(List.of()));

		eventService.getEvents(null, null, null, null, from, to);

		verify(eventRepository).findEvents(isNull(), isNull(), isNull(), isNull(), eq(from), eq(to), any(Pageable.class));
		verify(eventRepository, never()).findAll(any(Pageable.class));
	}

	@Test
	void getEvents_emptyResultReturnsEmptyPage() {
		when(eventRepository.findAll(any(Pageable.class)))
				.thenReturn(new PageImpl<>(List.of(), PaginationUtils.pageRequest(), 0));

		Page<EventCreateResponseObject> result = eventService.getEvents(null, null, null, null, null, null);

		assertThat(result.getContent()).isEmpty();
		assertThat(result.getTotalElements()).isZero();
	}

	@Test
	void verifyChain_emptyTableReturnsEmptyResult() {
		when(eventRepository.findAll(any(Sort.class))).thenReturn(List.of());

		ChainVerificationResult result = eventService.verifyChain();

		assertThat(result.getFirstInvalidRecordId()).isNull();
		assertThat(result.getViolationDescription()).isNull();
	}

	@Test
	void verifyChain_singleRecordReturnsEmptyResult() {
		when(eventRepository.findAll(any(Sort.class))).thenReturn(List.of(event(1L, "h1", null)));

		ChainVerificationResult result = eventService.verifyChain();

		assertThat(result.getFirstInvalidRecordId()).isNull();
		assertThat(result.getViolationDescription()).isNull();
	}

	@Test
	void verifyChain_validChainReturnsEmptyResult() {
		Event first = event(1L, "h1", null);
		Event second = event(2L, "h2", "h1");
		Event third = event(3L, "h3", "h2");
		when(eventRepository.findAll(any(Sort.class))).thenReturn(List.of(first, second, third));

		ChainVerificationResult result = eventService.verifyChain();

		assertThat(result.getFirstInvalidRecordId()).isNull();
		assertThat(result.getViolationDescription()).isNull();
	}

	@Test
	void verifyChain_mismatchStopsAtFirstInvalidRecord() {
		Event first = event(1L, "h1", null);
		Event second = event(2L, "h2", "wrong-hash");
		Event third = event(3L, "h3", "h2");
		when(eventRepository.findAll(any(Sort.class))).thenReturn(List.of(first, second, third));

		ChainVerificationResult result = eventService.verifyChain();

		assertThat(result.getFirstInvalidRecordId()).isEqualTo(2L);
		assertThat(result.getViolationDescription()).isEqualTo("HASH MISMATCH");
	}

	@Test
	void verifyChain_laterMismatchReportsThatRecordId() {
		Event first = event(1L, "h1", null);
		Event second = event(2L, "h2", "h1");
		Event third = event(3L, "h3", "broken");
		when(eventRepository.findAll(any(Sort.class))).thenReturn(List.of(first, second, third));

		ChainVerificationResult result = eventService.verifyChain();

		assertThat(result.getFirstInvalidRecordId()).isEqualTo(3L);
		assertThat(result.getViolationDescription()).isEqualTo("HASH MISMATCH");
	}

	@Test
	void checkForRetention_archivesOnlyActiveEventsOlderThanDays() {
		Event oldEvent = event(1L, "h1", null);
		oldEvent.setTimestamp(Instant.now().minus(100, ChronoUnit.DAYS));
		Event recentEvent = event(2L, "h2", "h1");
		recentEvent.setTimestamp(Instant.now().minus(10, ChronoUnit.DAYS));
		when(eventRepository.findByStatus(EventStatus.ACTIVE)).thenReturn(List.of(oldEvent, recentEvent));
		when(eventRepository.save(any(Event.class))).thenAnswer(invocation -> invocation.getArgument(0));

		RetentionCheckResult result = eventService.checkForRetention(90);

		assertThat(result.getDays()).isEqualTo(90);
		assertThat(result.getArchivedCount()).isEqualTo(1);
		assertThat(oldEvent.getStatus()).isEqualTo(EventStatus.ARCHIVED);
		assertThat(recentEvent.getStatus()).isEqualTo(EventStatus.ACTIVE);
		assertThat(oldEvent.getHash()).isEqualTo("h1");
		assertThat(oldEvent.getPreviousHash()).isNull();
		verify(eventRepository, times(1)).save(oldEvent);
		verify(eventRepository, never()).save(recentEvent);
	}

	@Test
	void checkForRetention_doesNotReprocessAlreadyArchivedEvents() {
		when(eventRepository.findByStatus(EventStatus.ACTIVE)).thenReturn(List.of());

		RetentionCheckResult result = eventService.checkForRetention(90);

		assertThat(result.getArchivedCount()).isZero();
		verify(eventRepository, never()).save(any(Event.class));
	}

	@Test
	void checkForRetention_validDaysKeepsChainIntactBeforeAndAfter() {
		Event first = event(1L, "h1", null);
		first.setTimestamp(Instant.now().minus(120, ChronoUnit.DAYS));
		Event second = event(2L, "h2", "h1");
		second.setTimestamp(Instant.now().minus(100, ChronoUnit.DAYS));
		Event third = event(3L, "h3", "h2");
		third.setTimestamp(Instant.now().minus(5, ChronoUnit.DAYS));
		List<Event> chain = List.of(first, second, third);

		when(eventRepository.findAll(any(Sort.class))).thenReturn(chain);
		ChainVerificationResult before = eventService.verifyChain();
		assertThat(before.getFirstInvalidRecordId()).isNull();
		assertThat(before.getViolationDescription()).isNull();

		when(eventRepository.findByStatus(EventStatus.ACTIVE)).thenReturn(chain);
		when(eventRepository.save(any(Event.class))).thenAnswer(invocation -> invocation.getArgument(0));

		RetentionCheckResult retention = eventService.checkForRetention(90);

		assertThat(retention.getArchivedCount()).isEqualTo(2);
		assertThat(first.getStatus()).isEqualTo(EventStatus.ARCHIVED);
		assertThat(second.getStatus()).isEqualTo(EventStatus.ARCHIVED);
		assertThat(third.getStatus()).isEqualTo(EventStatus.ACTIVE);
		assertThat(second.getPreviousHash()).isEqualTo(first.getHash());
		assertThat(third.getPreviousHash()).isEqualTo(second.getHash());

		ChainVerificationResult after = eventService.verifyChain();
		assertThat(after.getFirstInvalidRecordId()).isNull();
		assertThat(after.getViolationDescription()).isNull();
	}

	private Event event(Long id, String hash, String previousHash) {
		Event event = new Event();
		event.setId(id);
		event.setEventType("LOGIN");
		event.setActorId("actor-1");
		event.setResourceType("SESSION");
		event.setResourceId("s-" + id);
		event.setPayload("{}");
		event.setTimestamp(now);
		event.setHash(hash);
		event.setPreviousHash(previousHash);
		event.setStatus(EventStatus.ACTIVE);
		return event;
	}

	private Event committedEvent(Long id, String payload, String previousHash) {
		Event event = event(id, "placeholder", previousHash);
		String sealed = PayloadMerkleHasher.seal(payload);
		event.setPayload(sealed);
		event.setHash(PayloadMerkleHasher.computeEventHash(
				event.getEventType(), event.getActorId(), event.getResourceType(), event.getResourceId(),
				PayloadMerkleHasher.payloadRootFromPayload(sealed), event.getTimestamp(), previousHash));
		return event;
	}

	private List<Event> events(int fromId, int toIdInclusive) {
		List<Event> events = new ArrayList<>();
		for (int id = fromId; id <= toIdInclusive; id++) {
			events.add(event((long) id, "h" + id, id == 1 ? null : "h" + (id - 1)));
		}
		return events;
	}
}
