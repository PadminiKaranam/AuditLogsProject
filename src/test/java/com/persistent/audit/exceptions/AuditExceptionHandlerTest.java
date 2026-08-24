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
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import com.persistent.audit.model.EventCreateRequest;

import jakarta.validation.ConstraintViolationException;

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
		assertThat(response.getBody().toString()).doesNotContain("secret-payload");
	}

	@Test
	void handleBadRequestDoesNotEchoRawBody() throws Exception {
		assertThat(handler.handleBadRequest(new MissingServletRequestParameterException("days", "Integer"))
				.getBody().get("error")).isEqualTo("days is required");

		Method method = Dummy.class.getDeclaredMethod("header", String.class);
		MethodParameter parameter = new MethodParameter(method, 0);
		MissingRequestHeaderException missingHeader = new MissingRequestHeaderException("username", parameter);
		assertThat(handler.handleBadRequest(missingHeader).getBody().get("error")).isEqualTo("username is required");

		assertThat(handler.handleBadRequest(new HttpMessageNotReadableException("sensitive payload leaked",
				new org.springframework.mock.http.MockHttpInputMessage(new byte[0])))
				.getBody().get("error")).isEqualTo("Request body is malformed");

		MethodArgumentTypeMismatchException mismatch = new MethodArgumentTypeMismatchException(
				"x", Integer.class, "days", parameter, new IllegalArgumentException("bad"));
		assertThat(handler.handleBadRequest(new RuntimeException("ignored")).getBody().get("error"))
				.isEqualTo("Bad request");
	}

	@Test
	void remainingHandlersReturnExpectedStatuses() {
		assertThat(handler.handleConstraintViolation(new ConstraintViolationException("bad", java.util.Set.of()))
				.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
		assertThat(handler.handleTooLarge(new RequestTooLargeException("too big")).getStatusCode())
				.isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
		assertThat(handler.handleTooLarge(new MaxUploadSizeExceededException(10)).getStatusCode())
				.isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
		assertThat(handler.handleTooManyRequests(new TooManyRequestsException("slow down")).getStatusCode())
				.isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
		assertThat(handler.handleIllegalArgument(new IllegalArgumentException("nope")).getStatusCode())
				.isEqualTo(HttpStatus.BAD_REQUEST);
		assertThat(handler.handleNotFound(new NoSuchElementException("gone")).getStatusCode())
				.isEqualTo(HttpStatus.NOT_FOUND);
		assertThat(handler.handleJwt(new JwtAuthenticationException("expired")).getStatusCode())
				.isEqualTo(HttpStatus.UNAUTHORIZED);
		assertThat(handler.handleUserNotFound(new UserNotFoundException("no user")).getBody().get("error"))
				.isEqualTo("Invalid username or password");
		assertThat(handler.handleAccessForbidden(new AccessForbiddenException("secret reason")).getBody().get("error"))
				.isEqualTo("Access Forbidden");
		assertThat(ApiErrorResponse.of(HttpStatus.OK, "ok", Map.of("a", "b")).getBody()).containsKey("fields");
	}

	private static class Dummy {
		@SuppressWarnings("unused")
		void header(String username) {
		}
	}
}
