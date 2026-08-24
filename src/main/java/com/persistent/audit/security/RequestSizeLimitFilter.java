package com.persistent.audit.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestSizeLimitFilter extends OncePerRequestFilter {

	private final long maxRequestSizeBytes;

	public RequestSizeLimitFilter(
			@Value("${audit.http.max-request-size-bytes:1048576}") long maxRequestSizeBytes) {
		this.maxRequestSizeBytes = maxRequestSizeBytes;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		long contentLength = request.getContentLengthLong();
		if (contentLength > maxRequestSizeBytes) {
			response.setStatus(HttpStatus.PAYLOAD_TOO_LARGE.value());
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			response.getWriter().write("{\"status\":413,\"error\":\"Payload Too Large\"}");
			return;
		}
		filterChain.doFilter(request, response);
	}
}
