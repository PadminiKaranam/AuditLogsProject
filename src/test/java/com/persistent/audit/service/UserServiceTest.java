package com.persistent.audit.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.persistent.audit.exceptions.UserNotFoundException;
import com.persistent.audit.model.LoginResponse;
import com.persistent.audit.model.User;
import com.persistent.audit.repository.UserRepository;
import com.persistent.audit.security.JwtService;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

	@Mock
	private UserRepository userRepository;

	@Mock
	private PasswordEncoder passwordEncoder;

	@Mock
	private JwtService jwtService;

	@InjectMocks
	private UserService userService;

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
	}

	@Test
	void login_throwsWhenUserMissing() {
		when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

		assertThatThrownBy(() -> userService.login("ghost", "secret"))
				.isInstanceOf(UserNotFoundException.class)
				.hasMessage("Invalid username or password");
	}

	@Test
	void login_throwsWhenPasswordDoesNotMatch() {
		User user = new User(1L, "admin", "ADMIN", "admin@example.com", "encoded");
		when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
		when(passwordEncoder.matches("wrong", "encoded")).thenReturn(false);

		assertThatThrownBy(() -> userService.login("admin", "wrong"))
				.isInstanceOf(UserNotFoundException.class)
				.hasMessage("Invalid username or password");
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
}
