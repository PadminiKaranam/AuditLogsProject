package com.persistent.audit.security;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.persistent.audit.model.User;

public class AuditUserPrincipal implements UserDetails {

	private final User user;

	public AuditUserPrincipal(User user) {
		this.user = user;
	}

	public User getUser() {
		return user;
	}

	public String getEmail() {
		return user.getUserEmail();
	}

	public String getUserType() {
		return user.getUserType();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		String role = user.getUserType() == null ? "USER" : user.getUserType().trim().toUpperCase();
		return List.of(new SimpleGrantedAuthority("ROLE_" + role));
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
}
