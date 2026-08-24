package com.persistent.audit.security;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.persistent.audit.model.User;
import com.persistent.audit.repository.UserRepository;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class UserDataInitializer implements ApplicationRunner {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	public UserDataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public void run(ApplicationArguments args) {
		if (userRepository.count() == 0) {
			userRepository.save(user("admin", "ADMIN", "admin@example.com", "Admin@123"));
			userRepository.save(user("regulator", "REGULATOR", "regulator@example.com", "Regulator@123"));
			userRepository.save(user("viewer", "USER", "viewer@example.com", "User@123"));
			log.info("Seeded default USERS records for JWT login");
			return;
		}
		for (User existing : userRepository.findAll()) {
			if (!StringUtils.hasText(existing.getPassword())) {
				existing.setPassword(passwordEncoder.encode("ChangeMe@123"));
				userRepository.save(existing);
				log.info("Set default password for existing username={}", existing.getUsername());
			}
		}
	}

	private User user(String username, String userType, String email, String rawPassword) {
		User user = new User();
		user.setUsername(username);
		user.setUserType(userType);
		user.setUserEmail(email);
		user.setPassword(passwordEncoder.encode(rawPassword));
		return user;
	}
}
