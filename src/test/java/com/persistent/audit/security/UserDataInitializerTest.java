package com.persistent.audit.security;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.persistent.audit.model.User;
import com.persistent.audit.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class UserDataInitializerTest {

	@Mock
	private UserRepository userRepository;

	@Mock
	private PasswordEncoder passwordEncoder;

	@InjectMocks
	private UserDataInitializer initializer;

	@Test
	void seedsDefaultUsersWhenTableEmpty() throws Exception {
		when(userRepository.count()).thenReturn(0L);
		when(passwordEncoder.encode(any())).thenReturn("encoded");
		when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

		initializer.run(new DefaultApplicationArguments());

		ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
		verify(userRepository, times(3)).save(captor.capture());
		assertThatUsernames(captor.getAllValues());
	}

	@Test
	void fillsMissingPasswordsOnExistingUsers() throws Exception {
		User missing = new User(1L, "legacy", "ADMIN", "legacy@example.com", null);
		User alreadyHas = new User(2L, "ok", "USER", "ok@example.com", "present");
		when(userRepository.count()).thenReturn(2L);
		when(userRepository.findAll()).thenReturn(List.of(missing, alreadyHas));
		when(passwordEncoder.encode("ChangeMe@123")).thenReturn("new-hash");

		initializer.run(new DefaultApplicationArguments());

		verify(userRepository).save(missing);
		verify(userRepository, never()).save(alreadyHas);
		org.assertj.core.api.Assertions.assertThat(missing.getPassword()).isEqualTo("new-hash");
	}

	private void assertThatUsernames(List<User> users) {
		org.assertj.core.api.Assertions.assertThat(users)
				.extracting(User::getUsername)
				.containsExactly("admin", "regulator", "viewer");
		org.assertj.core.api.Assertions.assertThat(users)
				.extracting(User::getUserType)
				.containsExactly("ADMIN", "REGULATOR", "USER");
	}
}
