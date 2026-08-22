package com.persistent.audit.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RetentionCheckResult {

	private int days;
	private int archivedCount;
}
