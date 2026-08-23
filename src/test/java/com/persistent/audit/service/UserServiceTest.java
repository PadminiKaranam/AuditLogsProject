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

import com.persistent.audit.exceptions.UserNotFoundException;
import com.persistent.audit.model.User;
import com.persistent.audit.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

	@Mock
	private UserRepository userRepository;

	@InjectMocks
	private UserService userService;

	@Test
	void retrieveUserType_returnsTypeWhenUserExists() {
		User user = new User(1L, "admin", "ADMIN", "admin@example.com");
		when(userRepository.findByUserEmailAndUsername("admin@example.com", "admin"))
				.thenReturn(Optional.of(user));

		assertThat(userService.retrieveUserType("admin@example.com", "admin")).isEqualTo("ADMIN");
		verify(userRepository).findByUserEmailAndUsername("admin@example.com", "admin");
	}

	@Test
	void retrieveUserType_trimsEmailAndUsername() {
		User user = new User(2L, "reg", "REGULATOR", "reg@example.com");
		when(userRepository.findByUserEmailAndUsername("reg@example.com", "reg"))
				.thenReturn(Optional.of(user));

		assertThat(userService.retrieveUserType("  reg@example.com  ", "  reg  ")).isEqualTo("REGULATOR");
	}

	@Test
	void retrieveUserType_throwsWhenUserNotFound() {
		when(userRepository.findByUserEmailAndUsername("missing@example.com", "ghost"))
				.thenReturn(Optional.empty());

		assertThatThrownBy(() -> userService.retrieveUserType("missing@example.com", "ghost"))
				.isInstanceOf(UserNotFoundException.class)
				.hasMessageContaining("User not found");
	}

	@Test
	void retrieveUserType_throwsWhenEmailBlank() {
		assertThatThrownBy(() -> userService.retrieveUserType("  ", "admin"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("required");
	}

	@Test
	void retrieveUserType_throwsWhenUsernameBlank() {
		assertThatThrownBy(() -> userService.retrieveUserType("admin@example.com", null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("required");
	}
}
