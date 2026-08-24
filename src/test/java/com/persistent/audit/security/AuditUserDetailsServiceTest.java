package com.persistent.audit.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.persistent.audit.model.User;
import com.persistent.audit.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class AuditUserDetailsServiceTest {

	@Mock
	private UserRepository userRepository;

	@InjectMocks
	private AuditUserDetailsService userDetailsService;

	@Test
	void loadUserByUsername_returnsPrincipal() {
		User user = new User(1L, "admin", "ADMIN", "admin@example.com", "hash");
		when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));

		UserDetails details = userDetailsService.loadUserByUsername("admin");

		assertThat(details.getUsername()).isEqualTo("admin");
		assertThat(details.getAuthorities()).extracting(Object::toString).containsExactly("ROLE_ADMIN");
	}

	@Test
	void loadUserByUsername_throwsWhenMissing() {
		when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());
		assertThatThrownBy(() -> userDetailsService.loadUserByUsername("ghost"))
				.isInstanceOf(UsernameNotFoundException.class)
				.hasMessageContaining("ghost");
	}
}
