package com.persistent.audit.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class PayloadMerkleHasherTest {

	@Test
	void leafHash_isSha256OfKeyValueSalt() {
		assertThat(PayloadMerkleHasher.leafHash("name", "Alice", "SaltXYZ"))
				.isEqualTo(PayloadMerkleHasher.sha256("name" + "Alice" + "SaltXYZ"));
	}

	@Test
	void payloadRootHash_sortsByKeyNotInsertionOrder() {
		Map<String, String> insertionOrder = new LinkedHashMap<>();
		insertionOrder.put("name", "leaf-name");
		insertionOrder.put("account", "leaf-account");
		Map<String, String> reverse = new LinkedHashMap<>();
		reverse.put("account", "leaf-account");
		reverse.put("name", "leaf-name");

		assertThat(PayloadMerkleHasher.payloadRootHash(insertionOrder))
				.isEqualTo(PayloadMerkleHasher.payloadRootHash(reverse))
				.isEqualTo(PayloadMerkleHasher.sha256("leaf-account|leaf-name"));
	}

	@Test
	void seal_assignsUniqueSaltsAndMatchingLeafHashesInsidePayload() {
		String sealed = PayloadMerkleHasher.seal("{\"name\":\"Alice\",\"account\":\"12345\"}");
		var payload = PayloadMerkleHasher.parseObject(sealed);
		Map<String, String> salts = PayloadMerkleHasher.nestedStringMap(payload, PayloadMerkleHasher.SALTS_KEY);
		Map<String, String> leaves = PayloadMerkleHasher.nestedStringMap(payload, PayloadMerkleHasher.LEAVES_KEY);

		assertThat(payload.get("name").asString()).isEqualTo("Alice");
		assertThat(salts.get("name")).isNotEqualTo(salts.get("account"));
		assertThat(leaves.get("account"))
				.isEqualTo(PayloadMerkleHasher.leafHash("account", "12345", salts.get("account")));
		assertThat(PayloadMerkleHasher.payloadRootFromPayload(sealed))
				.isEqualTo(PayloadMerkleHasher.payloadRootHash(leaves));
	}

	@Test
	void payloadRootFromPayload_unchangedAfterRedaction() {
		String sealed = PayloadMerkleHasher.seal("{\"name\":\"Alice\",\"account\":\"12345\"}");
		String before = PayloadMerkleHasher.payloadRootFromPayload(sealed);
		String redacted = PayloadMerkleHasher.redact(sealed, List.of("account"));
		assertThat(PayloadMerkleHasher.parseObject(redacted).get("account").isNull()).isTrue();
		assertThat(PayloadMerkleHasher.nestedStringMap(
				PayloadMerkleHasher.parseObject(redacted), PayloadMerkleHasher.SALTS_KEY)).doesNotContainKey("account");
		assertThat(PayloadMerkleHasher.payloadRootFromPayload(redacted)).isEqualTo(before);
	}

	@Test
	void computeEventHash_usesPayloadRootHashNotRawPayload() {
		Instant timestamp = Instant.parse("2026-08-22T10:15:30Z");
		String withRoot = PayloadMerkleHasher.computeEventHash(
				"LOGIN", "a", "SESSION", "s", "root-hash", timestamp, null);
		String withRaw = PayloadMerkleHasher.computeEventHash(
				"LOGIN", "a", "SESSION", "s", "{\"name\":\"Alice\"}", timestamp, null);
		assertThat(withRoot).isNotEqualTo(withRaw).hasSize(64);
	}

	@Test
	void parseObject_rejectsNonObjectJson() {
		assertThatThrownBy(() -> PayloadMerkleHasher.parseObject("\"just a string\""))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void seal_emptyObjectStaysEmpty() {
		assertThat(PayloadMerkleHasher.seal("{}")).isEqualTo("{}");
	}
}
