package com.persistent.audit.util;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

public final class PaginationUtils {

	public static final int PAGE_SIZE = 10;

	private PaginationUtils() {
	}

	public static Pageable pageRequest() {
		return pageRequest(0);
	}

	public static Pageable pageRequest(int page) {
		int pageNumber = Math.max(page, 0);
		return PageRequest.of(pageNumber, PAGE_SIZE, Sort.by(Sort.Direction.DESC, "timestamp", "id"));
	}
}
