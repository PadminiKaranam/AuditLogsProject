package com.persistent.audit.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EventCreateRequest {

	@NotBlank(message = "eventType is required")
	@Size(max = 100)
	private String eventType;

	@NotBlank(message = "actorId is required")
	@Size(max = 255)
	private String actorId;

	@NotBlank(message = "resourceType is required")
	@Size(max = 100)
	private String resourceType;

	@NotBlank(message = "resourceId is required")
	@Size(max = 255)
	private String resourceId;

	@NotBlank(message = "payload is required")
	@Size(max = 8192, message = "payload exceeds maximum allowed size")
	private String payload;
}
