package com.persistent.audit.exceptions;

public class RequestTooLargeException extends RuntimeException {

	public RequestTooLargeException(String message) {
		super(message);
	}
}
