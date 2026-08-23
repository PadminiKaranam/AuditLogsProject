package com.persistent.audit.exceptions;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public final class ApiErrorResponse {

	private ApiErrorResponse() {
	}

	public static ResponseEntity<Map<String, Object>> of(HttpStatus status, String message, Map<String, String> fields) {
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("status", status.value());
		body.put("error", message);
		if (fields != null) {
			body.put("fields", fields);
		}
		return ResponseEntity.status(status).body(body);
	}
}
