package com.persistent.audit.model;

import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BundleExportStructureResponse {

	private Long id;
	private String eventType;
	private String actorId;
	private String resourceType;
	private String resourceId;
	private String payload;
	private Instant timestamp;
	private String chainMetadata;
}
