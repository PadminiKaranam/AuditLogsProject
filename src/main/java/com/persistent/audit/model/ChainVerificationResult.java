package com.persistent.audit.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ChainVerificationResult {

	private Long firstInvalidRecordId;
	private String violationDescription;
}
