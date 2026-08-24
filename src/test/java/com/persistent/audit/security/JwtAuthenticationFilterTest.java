package com.persistent.audit.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.persistent.audit.exceptions.JwtAuthenticationException;
import com.persistent.audit.model.User;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

	@Mock
	private JwtService jwtService;

	@Mock
	private UserDetailsService userDetailsService;

	private JwtAuthenticationFilter filter;

	@BeforeEach
	void setUp() {
		filter = new JwtAuthenticationFilter(jwtService, userDetailsService);
		SecurityContextHolder.clearContext();
	}

	@AfterEach
	void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void skipsLoginAndH2Console() throws Exception {
		MockHttpServletRequest login = new MockHttpServletRequest("POST", "/audit/auth/login");
		login.setServletPath("/audit/auth/login");
		assertThatSkipped(login);

		MockHttpServletRequest h2 = new MockHttpServletRequest("GET", "/h2-console/login.do");
		h2.setServletPath("/h2-console/login.do");
		assertThatSkipped(h2);
	}

	@Test
	void continuesWhenAuthorizationHeaderBlank() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/audit/verify");
		request.setServletPath("/audit/verify");
		request.addHeader("Authorization", "   ");
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();

		filter.doFilter(request, response, chain);

		assertThat(chain.getRequest()).isSameAs(request);
		verify(jwtService, never()).extractUsername(any());
	}

	@Test
	void continuesWhenAuthorizationHeaderMissing() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/audit/verify");
		request.setServletPath("/audit/verify");
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();

		filter.doFilter(request, response, chain);

		assertThat(chain.getRequest()).isSameAs(request);
		verify(jwtService, never()).extractUsername(any());
	}

	@Test
	void rejectsNonBearerAuthorizationHeader() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/audit/verify");
		request.setServletPath("/audit/verify");
		request.addHeader("Authorization", "Basic abc");
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(request, response, new MockFilterChain());

		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getContentAsString()).contains("Bearer");
	}

	@Test
	void rejectsBlankBearerToken() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/audit/verify");
		request.setServletPath("/audit/verify");
		request.addHeader("Authorization", "Bearer   ");
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(request, response, new MockFilterChain());

		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getContentAsString()).contains("JWT is missing");
	}

	@Test
	void setsAuthenticationForValidToken() throws Exception {
		User user = new User(1L, "admin", "ADMIN", "admin@example.com", "hash");
		AuditUserPrincipal principal = new AuditUserPrincipal(user);
		when(jwtService.extractUsername("good-token")).thenReturn("admin");
		when(userDetailsService.loadUserByUsername("admin")).thenReturn(principal);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/audit/verify");
		request.setServletPath("/audit/verify");
		request.addHeader("Authorization", "Bearer good-token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();

		filter.doFilter(request, response, chain);

		assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal()).isSameAs(principal);
		assertThat(chain.getRequest()).isSameAs(request);
	}

	@Test
	void writesUnauthorizedWhenTokenInvalid() throws Exception {
		when(jwtService.extractUsername("bad")).thenThrow(new JwtAuthenticationException("JWT has expired"));
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/audit/verify");
		request.setServletPath("/audit/verify");
		request.addHeader("Authorization", "Bearer bad");
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(request, response, new MockFilterChain());

		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getContentAsString()).contains("JWT has expired");
	}

	@Test
	void writesUnauthorizedWhenUserMissing() throws Exception {
		when(jwtService.extractUsername("token")).thenReturn("gone");
		when(userDetailsService.loadUserByUsername("gone")).thenThrow(new UsernameNotFoundException("gone"));
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/audit/verify");
		request.setServletPath("/audit/verify");
		request.addHeader("Authorization", "Bearer token");
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(request, response, new MockFilterChain());

		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	void doesNotReplaceExistingAuthentication() throws Exception {
		User user = new User(1L, "admin", "ADMIN", "admin@example.com", "hash");
		AuditUserPrincipal principal = new AuditUserPrincipal(user);
		SecurityContextHolder.getContext().setAuthentication(
				new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
						principal, null, principal.getAuthorities()));
		when(jwtService.extractUsername("token")).thenReturn("admin");

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/audit/verify");
		request.setServletPath("/audit/verify");
		request.addHeader("Authorization", "Bearer token");

		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

		verify(userDetailsService, never()).loadUserByUsername(any());
	}

	@Test
	void escapeHandlesQuotesNullAndBackslash() throws Exception {
		MockHttpServletResponse quoted = new MockHttpServletResponse();
		JwtAuthenticationFilter.writeUnauthorized(quoted, "say \"hi\" and \\path");
		assertThat(quoted.getContentAsString()).contains("\\\"").contains("\\\\path");
		MockHttpServletResponse nullMessage = new MockHttpServletResponse();
		JwtAuthenticationFilter.writeUnauthorized(nullMessage, null);
		assertThat(nullMessage.getContentAsString()).contains("Unauthorized");
	}

	private void assertThatSkipped(MockHttpServletRequest request) throws Exception {
		MockFilterChain chain = new MockFilterChain();
		filter.doFilter(request, new MockHttpServletResponse(), chain);
		assertThat(chain.getRequest()).isSameAs(request);
		verify(jwtService, never()).extractUsername(any());
	}
}
