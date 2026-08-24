package com.persistent.audit.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {

	private String accessToken;
	private String tokenType;
	private long expiresIn;
	private String username;
	private String email;
	private String userType;
}
