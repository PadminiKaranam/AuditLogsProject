package com.persistent.audit.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.persistent.audit.exceptions.TooManyRequestsException;

import com.persistent.audit.exceptions.UserNotFoundException;
import com.persistent.audit.model.LoginResponse;
import com.persistent.audit.model.User;
import com.persistent.audit.repository.UserRepository;
import com.persistent.audit.security.JwtService;
import com.persistent.audit.security.LoginRateLimiter;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

	@Mock
	private UserRepository userRepository;

	@Mock
	private PasswordEncoder passwordEncoder;

	@Mock
	private JwtService jwtService;

	@Mock
	private LoginRateLimiter loginRateLimiter;

	@InjectMocks
	private UserService userService;

	@AfterEach
	void clearRequest() {
		RequestContextHolder.resetRequestAttributes();
	}

	@Test
	void login_returnsJwtWhenCredentialsMatch() {
		User user = new User(1L, "admin", "ADMIN", "admin@example.com", "encoded");
		when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
		when(passwordEncoder.matches("Admin@123", "encoded")).thenReturn(true);
		when(jwtService.generateToken(user)).thenReturn("signed-jwt");
		when(jwtService.getExpirationMs()).thenReturn(3600000L);

		LoginResponse response = userService.login("  admin  ", "Admin@123");

		assertThat(response.getAccessToken()).isEqualTo("signed-jwt");
		assertThat(response.getTokenType()).isEqualTo("Bearer");
		assertThat(response.getExpiresIn()).isEqualTo(3600000L);
		assertThat(response.getUsername()).isEqualTo("admin");
		assertThat(response.getEmail()).isEqualTo("admin@example.com");
		assertThat(response.getUserType()).isEqualTo("ADMIN");
		verify(userRepository).findByUsername("admin");
		verify(loginRateLimiter).reset("  admin  ", "unknown");
	}

	@Test
	void login_throwsWhenUserMissing() {
		when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

		assertThatThrownBy(() -> userService.login("ghost", "secret"))
				.isInstanceOf(UserNotFoundException.class)
				.hasMessage("Invalid username or password");
		verify(loginRateLimiter).recordFailure("ghost", "unknown");
	}

	@Test
	void login_throwsWhenPasswordDoesNotMatch() {
		User user = new User(1L, "admin", "ADMIN", "admin@example.com", "encoded");
		when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
		when(passwordEncoder.matches("wrong", "encoded")).thenReturn(false);

		assertThatThrownBy(() -> userService.login("admin", "wrong"))
				.isInstanceOf(UserNotFoundException.class)
				.hasMessage("Invalid username or password");
		verify(loginRateLimiter).recordFailure("admin", "unknown");
	}

	@Test
	void login_throwsWhenStoredPasswordBlank() {
		User user = new User(1L, "admin", "ADMIN", "admin@example.com", "  ");
		when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));

		assertThatThrownBy(() -> userService.login("admin", "Admin@123"))
				.isInstanceOf(UserNotFoundException.class);
	}

	@Test
	void login_throwsWhenUsernameBlank() {
		assertThatThrownBy(() -> userService.login("  ", "secret"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("required");
	}

	@Test
	void login_throwsWhenPasswordBlank() {
		assertThatThrownBy(() -> userService.login("admin", null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("required");
	}

	@Test
	void login_blockedWhenRateLimitExceeded() {
		doThrow(new TooManyRequestsException("Too Many Requests")).when(loginRateLimiter).check("admin", "unknown");
		assertThatThrownBy(() -> userService.login("admin", "Admin@123"))
				.isInstanceOf(TooManyRequestsException.class);
	}

	@Test
	void login_usesForwardedClientIp() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("X-Forwarded-For", "203.0.113.10, 10.0.0.1");
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
		when(userRepository.findByUsername("admin")).thenReturn(Optional.empty());

		assertThatThrownBy(() -> userService.login("admin", "secret"))
				.isInstanceOf(UserNotFoundException.class);
		verify(loginRateLimiter).check("admin", "203.0.113.10");
		verify(loginRateLimiter).recordFailure("admin", "203.0.113.10");
	}

	@Test
	void login_usesUnknownWhenRemoteAddrMissing() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRemoteAddr(null);
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
		when(userRepository.findByUsername("admin")).thenReturn(Optional.empty());

		assertThatThrownBy(() -> userService.login("admin", "secret"))
				.isInstanceOf(UserNotFoundException.class);
		verify(loginRateLimiter).check("admin", "unknown");
	}
}
