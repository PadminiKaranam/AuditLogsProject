package com.persistent.audit.util;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

class PaginationUtilsTest {

	@Test
	void pageRequest_defaultPageIsZeroAndSizeIsTen() {
		Pageable pageable = PaginationUtils.pageRequest();

		assertThat(pageable.getPageNumber()).isEqualTo(0);
		assertThat(pageable.getPageSize()).isEqualTo(10);
		assertThat(pageable.getSort().getOrderFor("timestamp").getDirection()).isEqualTo(Sort.Direction.DESC);
	}

	@Test
	void pageRequest_negativePageBecomesZero() {
		assertThat(PaginationUtils.pageRequest(-1).getPageNumber()).isEqualTo(0);
	}

	@Test
	void pageRequest_keepsRequestedPageWhenNonNegative() {
		assertThat(PaginationUtils.pageRequest(3).getPageNumber()).isEqualTo(3);
		assertThat(PaginationUtils.pageRequest(3).getPageSize()).isEqualTo(PaginationUtils.PAGE_SIZE);
	}

	@Test
	void privateConstructorIsInvokedForCoverage() throws Exception {
		var constructor = PaginationUtils.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertThat(constructor.newInstance()).isNotNull();
	}
}
