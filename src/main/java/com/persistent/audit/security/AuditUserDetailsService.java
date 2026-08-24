package com.persistent.audit.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.persistent.audit.repository.UserRepository;

@Service
public class AuditUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	public AuditUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) {
		return userRepository.findByUsername(username)
				.map(AuditUserPrincipal::new)
				.orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
	}
}
