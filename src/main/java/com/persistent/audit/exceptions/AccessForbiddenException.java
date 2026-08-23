package com.persistent.audit.exceptions;

public class AccessForbiddenException extends RuntimeException {

	public AccessForbiddenException(String message) {
		super(message);
	}
}
