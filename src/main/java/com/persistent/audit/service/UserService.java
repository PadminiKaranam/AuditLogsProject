package com.persistent.audit.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.persistent.audit.exceptions.UserNotFoundException;
import com.persistent.audit.model.LoginResponse;
import com.persistent.audit.model.User;
import com.persistent.audit.repository.UserRepository;
import com.persistent.audit.security.JwtService;
import com.persistent.audit.security.LoginRateLimiter;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class UserService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final LoginRateLimiter loginRateLimiter;

	public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService,
			LoginRateLimiter loginRateLimiter) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.loginRateLimiter = loginRateLimiter;
	}

	public LoginResponse login(String username, String password) {
		if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
			throw new IllegalArgumentException("username and password are required");
		}
		String clientIp = clientIp();
		loginRateLimiter.check(username, clientIp);
		User user = userRepository.findByUsername(username.trim())
				.orElse(null);
		if (user == null || !StringUtils.hasText(user.getPassword())
				|| !passwordEncoder.matches(password, user.getPassword())) {
			loginRateLimiter.recordFailure(username, clientIp);
			throw new UserNotFoundException("Invalid username or password");
		}
		loginRateLimiter.reset(username, clientIp);
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

	private String clientIp() {
		ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		if (attributes == null) {
			return "unknown";
		}
		HttpServletRequest request = attributes.getRequest();
		String forwarded = request.getHeader("X-Forwarded-For");
		if (StringUtils.hasText(forwarded)) {
			return forwarded.split(",")[0].trim();
		}
		return request.getRemoteAddr() == null ? "unknown" : request.getRemoteAddr();
	}
}
