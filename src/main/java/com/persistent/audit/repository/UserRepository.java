package com.persistent.audit.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.persistent.audit.model.User;

public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findByUsername(String username);

	Optional<User> findByUserEmailAndUsername(String userEmail, String username);
}
