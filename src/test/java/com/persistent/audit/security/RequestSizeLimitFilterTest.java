package com.persistent.audit.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class RequestSizeLimitFilterTest {

	@Test
	void rejectsDeclaredContentLengthAboveLimit() throws Exception {
		RequestSizeLimitFilter filter = new RequestSizeLimitFilter(100);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/audit/createEvent");
		request.setContent(new byte[101]);
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(request, response, new MockFilterChain());

		assertThat(response.getStatus()).isEqualTo(413);
		assertThat(response.getContentAsString()).isEqualTo("{\"status\":413,\"error\":\"Payload Too Large\"}");
	}

	@Test
	void allowsRequestWithinLimit() throws Exception {
		RequestSizeLimitFilter filter = new RequestSizeLimitFilter(100);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/audit/createEvent");
		request.setContent("{}".getBytes());
		MockFilterChain chain = new MockFilterChain();
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(request, response, chain);

		assertThat(response.getStatus()).isNotEqualTo(413);
		assertThat(chain.getRequest()).isSameAs(request);
	}
}
