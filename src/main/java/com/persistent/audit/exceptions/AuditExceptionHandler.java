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
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

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
		log.error("Validation exception on request fields={}", fieldErrors, ex);
		return ApiErrorResponse.of(HttpStatus.BAD_REQUEST, "Validation failed", fieldErrors);
	}

	@ExceptionHandler({ HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class,
			MissingServletRequestParameterException.class, MissingRequestHeaderException.class })
	public ResponseEntity<Map<String, Object>> handleBadRequest(Exception ex) {
		log.error("Bad request exception: {}", ex.getMessage(), ex);
		return ApiErrorResponse.of(HttpStatus.BAD_REQUEST, ex.getMessage(), null);
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
		log.error("User authentication failed: {}", ex.getMessage(), ex);
		return ApiErrorResponse.of(HttpStatus.UNAUTHORIZED, ex.getMessage(), null);
	}

	@ExceptionHandler(AccessForbiddenException.class)
	public ResponseEntity<Map<String, Object>> handleAccessForbidden(AccessForbiddenException ex) {
		log.error("Access forbidden: {}", ex.getMessage(), ex);
		return ApiErrorResponse.of(HttpStatus.FORBIDDEN, ex.getMessage(), null);
	}
}
