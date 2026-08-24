package com.persistent.audit.security;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.persistent.audit.exceptions.JwtAuthenticationException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	public static final String BEARER_PREFIX = "Bearer ";

	private final JwtService jwtService;
	private final UserDetailsService userDetailsService;

	public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
		this.jwtService = jwtService;
		this.userDetailsService = userDetailsService;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		String path = request.getServletPath();
		return path.equals("/audit/auth/login") || path.startsWith("/h2-console");
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String header = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (header == null || header.isBlank()) {
			filterChain.doFilter(request, response);
			return;
		}
		if (!header.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
			writeUnauthorized(response, "Authorization header must be Bearer token");
			return;
		}
		String token = header.substring(BEARER_PREFIX.length()).trim();
		if (token.isEmpty()) {
			writeUnauthorized(response, "JWT is missing");
			return;
		}
		try {
			String username = jwtService.extractUsername(token);
			if (SecurityContextHolder.getContext().getAuthentication() == null) {
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
			filterChain.doFilter(request, response);
		} catch (JwtAuthenticationException | org.springframework.security.core.userdetails.UsernameNotFoundException ex) {
			log.debug("JWT authentication failed: {}", ex.getMessage());
			writeUnauthorized(response, ex.getMessage());
		}
	}

	static void writeUnauthorized(HttpServletResponse response, String message) throws IOException {
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.getWriter().write("{\"status\":401,\"error\":\"" + escape(message) + "\"}");
	}

	private static String escape(String message) {
		if (message == null) {
			return "Unauthorized";
		}
		return message.replace("\\", "\\\\").replace("\"", "\\\"");
	}
}
