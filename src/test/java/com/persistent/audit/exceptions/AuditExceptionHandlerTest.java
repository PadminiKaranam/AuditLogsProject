package com.persistent.audit.exceptions;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.NoSuchElementException;

import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;

import com.persistent.audit.model.EventCreateRequest;

class AuditExceptionHandlerTest {

	private final AuditExceptionHandler handler = new AuditExceptionHandler();

	@Test
	void handleValidationMergesDuplicateFieldErrorsAndUsesDefaultMessage() throws Exception {
		BeanPropertyBindingResult binding = new BeanPropertyBindingResult(new EventCreateRequest(), "request");
		binding.addError(new FieldError("request", "eventType", "first"));
		binding.addError(new FieldError("request", "eventType", "second"));
		binding.addError(new FieldError("request", "actorId", null, false, null, null, null));
		Method method = AuditExceptionHandler.class.getDeclaredMethod("handleValidation", MethodArgumentNotValidException.class);
		MethodParameter parameter = new MethodParameter(method, 0);
		MethodArgumentNotValidException ex = new MethodArgumentNotValidException(parameter, binding);

		ResponseEntity<Map<String, Object>> response = handler.handleValidation(ex);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
		@SuppressWarnings("unchecked")
		Map<String, String> fields = (Map<String, String>) response.getBody().get("fields");
		assertThat(fields.get("eventType")).isEqualTo("first");
		assertThat(fields.get("actorId")).isEqualTo("invalid");
	}

	@Test
	void handleBadRequestCoversHeaderAndParameterExceptions() throws Exception {
		assertThat(handler.handleBadRequest(new MissingServletRequestParameterException("days", "Integer"))
				.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

		Method method = Dummy.class.getDeclaredMethod("header", String.class);
		MethodParameter parameter = new MethodParameter(method, 0);
		MissingRequestHeaderException missingHeader = new MissingRequestHeaderException("username", parameter);
		assertThat(handler.handleBadRequest(missingHeader).getBody().get("status")).isEqualTo(400);

		assertThat(handler.handleBadRequest(new HttpMessageNotReadableException("bad json",
				new org.springframework.mock.http.MockHttpInputMessage(new byte[0])))
				.getBody().get("error")).isEqualTo("bad json");
	}

	@Test
	void remainingHandlersReturnExpectedStatuses() {
		assertThat(handler.handleIllegalArgument(new IllegalArgumentException("nope")).getStatusCode())
				.isEqualTo(HttpStatus.BAD_REQUEST);
		assertThat(handler.handleNotFound(new NoSuchElementException("gone")).getStatusCode())
				.isEqualTo(HttpStatus.NOT_FOUND);
		assertThat(handler.handleJwt(new JwtAuthenticationException("expired")).getStatusCode())
				.isEqualTo(HttpStatus.UNAUTHORIZED);
		assertThat(handler.handleUserNotFound(new UserNotFoundException("no user")).getStatusCode())
				.isEqualTo(HttpStatus.UNAUTHORIZED);
		assertThat(handler.handleAccessForbidden(new AccessForbiddenException("Access Forbidden")).getStatusCode())
				.isEqualTo(HttpStatus.FORBIDDEN);
		assertThat(ApiErrorResponse.of(HttpStatus.OK, "ok", Map.of("a", "b")).getBody()).containsKey("fields");
	}

	private static class Dummy {
		@SuppressWarnings("unused")
		void header(String username) {
		}
	}
}
