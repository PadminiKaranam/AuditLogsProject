package com.persistent.audit.exceptions;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestControllerAdvice
public class AuditExceptionHandler {

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
		Map<String, String> fieldErrors = ex.getBindingResult().getFieldErrors().stream()
				.collect(Collectors.toMap(
						error -> error.getField(),
						error -> error.getDefaultMessage() != null ? error.getDefaultMessage() : "invalid",
						(first, ignored) -> first,
						LinkedHashMap::new));
		log.error("Validation exception on request fieldNames={}", fieldErrors.keySet());
		return ApiErrorResponse.of(HttpStatus.BAD_REQUEST, "Validation failed", fieldErrors);
	}

	@ExceptionHandler({ ConstraintViolationException.class, HandlerMethodValidationException.class })
	public ResponseEntity<Map<String, Object>> handleConstraintViolation(Exception ex) {
		log.error("Constraint validation failed");
		return ApiErrorResponse.of(HttpStatus.BAD_REQUEST, "Validation failed", null);
	}

	@ExceptionHandler({ HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class,
			MissingServletRequestParameterException.class, MissingRequestHeaderException.class })
	public ResponseEntity<Map<String, Object>> handleBadRequest(Exception ex) {
		log.error("Bad request exception: {}", safeMessage(ex));
		return ApiErrorResponse.of(HttpStatus.BAD_REQUEST, safeMessage(ex), null);
	}

	@ExceptionHandler({ MaxUploadSizeExceededException.class, RequestTooLargeException.class })
	public ResponseEntity<Map<String, Object>> handleTooLarge(Exception ex) {
		log.error("Request exceeded configured size limit");
		return ApiErrorResponse.of(HttpStatus.PAYLOAD_TOO_LARGE, "Payload Too Large", null);
	}

	@ExceptionHandler(TooManyRequestsException.class)
	public ResponseEntity<Map<String, Object>> handleTooManyRequests(TooManyRequestsException ex) {
		log.error("Login rate limit exceeded");
		return ApiErrorResponse.of(HttpStatus.TOO_MANY_REQUESTS, "Too Many Requests", null);
	}

	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException ex) {
		log.error("Illegal argument: {}", ex.getMessage(), ex);
		return ApiErrorResponse.of(HttpStatus.BAD_REQUEST, ex.getMessage(), null);
	}

	@ExceptionHandler(NoSuchElementException.class)
	public ResponseEntity<Map<String, Object>> handleNotFound(NoSuchElementException ex) {
		log.error("Resource not found: {}", ex.getMessage(), ex);
		return ApiErrorResponse.of(HttpStatus.NOT_FOUND, ex.getMessage(), null);
	}

	@ExceptionHandler(JwtAuthenticationException.class)
	public ResponseEntity<Map<String, Object>> handleJwt(JwtAuthenticationException ex) {
		log.error("JWT authentication failed: {}", ex.getMessage(), ex);
		return ApiErrorResponse.of(HttpStatus.UNAUTHORIZED, ex.getMessage(), null);
	}

	@ExceptionHandler(UserNotFoundException.class)
	public ResponseEntity<Map<String, Object>> handleUserNotFound(UserNotFoundException ex) {
		log.error("User authentication failed");
		return ApiErrorResponse.of(HttpStatus.UNAUTHORIZED, "Invalid username or password", null);
	}

	@ExceptionHandler(AccessForbiddenException.class)
	public ResponseEntity<Map<String, Object>> handleAccessForbidden(AccessForbiddenException ex) {
		log.error("Access forbidden");
		return ApiErrorResponse.of(HttpStatus.FORBIDDEN, "Access Forbidden", null);
	}

	private String safeMessage(Exception ex) {
		if (ex instanceof HttpMessageNotReadableException) {
			return "Request body is malformed";
		}
		if (ex instanceof MethodArgumentTypeMismatchException) {
			return "Invalid request parameter";
		}
		if (ex instanceof MissingServletRequestParameterException missing) {
			return missing.getParameterName() + " is required";
		}
		if (ex instanceof MissingRequestHeaderException missing) {
			return missing.getHeaderName() + " is required";
		}
		return "Bad request";
	}
}
