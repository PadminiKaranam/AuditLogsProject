package com.persistent.audit.service;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.persistent.audit.exceptions.UserNotFoundException;
import com.persistent.audit.model.User;
import com.persistent.audit.repository.UserRepository;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class UserService {

	private final UserRepository userRepository;

	public UserService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	public String retrieveUserType(String userEmail, String userName) {
		if (!StringUtils.hasText(userEmail) || !StringUtils.hasText(userName)) {
			throw new IllegalArgumentException("username and useremail are required");
		}
		log.debug("Retrieving userType for username={}", userName);
		User user = userRepository.findByUserEmailAndUsername(userEmail.trim(), userName.trim())
				.orElseThrow(() -> new UserNotFoundException(
						"User not found for the given username and useremail"));
		log.info("Resolved userType={} for username={}", user.getUserType(), userName);
		return user.getUserType();
	}
}
