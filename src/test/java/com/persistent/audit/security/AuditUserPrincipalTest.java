package com.persistent.audit.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.persistent.audit.model.User;

class AuditUserPrincipalTest {

	@Test
	void exposesUserFieldsAndRoleAuthority() {
		User user = new User(3L, "regulator", "REGULATOR", "reg@example.com", "secret");
		AuditUserPrincipal principal = new AuditUserPrincipal(user);

		assertThat(principal.getUser()).isSameAs(user);
		assertThat(principal.getEmail()).isEqualTo("reg@example.com");
		assertThat(principal.getUserType()).isEqualTo("REGULATOR");
		assertThat(principal.getPassword()).isEqualTo("secret");
		assertThat(principal.getUsername()).isEqualTo("regulator");
		assertThat(principal.isAccountNonExpired()).isTrue();
		assertThat(principal.isAccountNonLocked()).isTrue();
		assertThat(principal.isCredentialsNonExpired()).isTrue();
		assertThat(principal.isEnabled()).isTrue();
		assertThat(principal.getAuthorities()).extracting(Object::toString).containsExactly("ROLE_REGULATOR");
	}

	@Test
	void defaultsRoleWhenUserTypeMissing() {
		User user = new User(4L, "anon", null, "a@b.c", "x");
		assertThat(new AuditUserPrincipal(user).getAuthorities())
				.extracting(Object::toString)
				.containsExactly("ROLE_USER");
	}

	@Test
	void trimsAndUppercasesUserType() {
		User user = new User(5L, "a", " regulator ", "a@b.c", "x");
		assertThat(new AuditUserPrincipal(user).getAuthorities())
				.extracting(Object::toString)
				.containsExactly("ROLE_REGULATOR");
	}
}
