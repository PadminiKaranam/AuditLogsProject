package com.persistent.audit.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.persistent.audit.exceptions.UserNotFoundException;
import com.persistent.audit.model.LoginResponse;
import com.persistent.audit.model.User;
import com.persistent.audit.repository.UserRepository;
import com.persistent.audit.security.JwtService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class UserService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;

	public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
	}

	public LoginResponse login(String username, String password) {
		if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
			throw new IllegalArgumentException("username and password are required");
		}
		User user = userRepository.findByUsername(username.trim())
				.orElseThrow(() -> new UserNotFoundException("Invalid username or password"));
		if (!StringUtils.hasText(user.getPassword()) || !passwordEncoder.matches(password, user.getPassword())) {
			throw new UserNotFoundException("Invalid username or password");
		}
		String token = jwtService.generateToken(user);
		log.info("Issued JWT for username={} userType={}", user.getUsername(), user.getUserType());
		return new LoginResponse(
				token,
				"Bearer",
				jwtService.getExpirationMs(),
				user.getUsername(),
				user.getUserEmail(),
				user.getUserType());
	}
}
