package com.persistent.audit.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
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

import com.persistent.audit.model.ChainVerificationResult;
import com.persistent.audit.model.Event;
import com.persistent.audit.model.EventCreateResponseObject;
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
		assertThat(result.getId()).isEqualTo(1L);
		assertThat(result.getEventType()).isEqualTo("LOGIN");
	}

	@Test
	void createEvent_linksPreviousHashFromLatestEvent() {
		Event previous = event(1L, "h-prev", null);
		when(eventRepository.findTopByOrderByIdDesc()).thenReturn(Optional.of(previous));
		when(eventRepository.save(any(Event.class))).thenAnswer(invocation -> {
			Event event = invocation.getArgument(0);
			event.setId(2L);
			return event;
		});

		eventService.createEvent("LOGOUT", "actor-1", "SESSION", "s-1", "{}");

		ArgumentCaptor<Event> captor = ArgumentCaptor.forClass(Event.class);
		verify(eventRepository).save(captor.capture());
		assertThat(captor.getValue().getPreviousHash()).isEqualTo("h-prev");
		assertThat(captor.getValue().getHash()).isNotEqualTo("h-prev");
	}

	@Test
	void createEvent_blankPayloadNormalizedToEmptyJson() {
		when(eventRepository.findTopByOrderByIdDesc()).thenReturn(Optional.empty());
		when(eventRepository.save(any(Event.class))).thenAnswer(invocation -> invocation.getArgument(0));

		eventService.createEvent("LOGIN", "actor-1", "SESSION", "s-1", "  ");

		ArgumentCaptor<Event> captor = ArgumentCaptor.forClass(Event.class);
		verify(eventRepository).save(captor.capture());
		assertThat(captor.getValue().getPayload()).isEqualTo("{}");
	}

	@Test
	void createEvent_nullPayloadNormalizedToEmptyJson() {
		when(eventRepository.findTopByOrderByIdDesc()).thenReturn(Optional.empty());
		when(eventRepository.save(any(Event.class))).thenAnswer(invocation -> invocation.getArgument(0));

		eventService.createEvent("LOGIN", "actor-1", "SESSION", "s-1", null);

		ArgumentCaptor<Event> captor = ArgumentCaptor.forClass(Event.class);
		verify(eventRepository).save(captor.capture());
		assertThat(captor.getValue().getPayload()).isEqualTo("{}");
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
