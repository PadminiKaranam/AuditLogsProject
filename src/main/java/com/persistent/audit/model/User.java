package com.persistent.audit.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "USERS")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "user_id")
	private Long userId;

	@NotBlank
	@Size(max = 100)
	@Column(name = "username", nullable = false, length = 100)
	private String username;

	@NotBlank
	@Size(max = 50)
	@Column(name = "user_type", nullable = false, length = 50)
	private String userType;

	@NotBlank
	@Size(max = 255)
	@Column(name = "user_email", nullable = false, unique = true, length = 255)
	private String userEmail;
}
