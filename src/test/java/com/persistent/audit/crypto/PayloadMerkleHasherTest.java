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
				PayloadMerkleHasher.parseObject(redacted), PayloadMerkleHasher.SALTS_KEY)).containsKey("account");
		assertThat(PayloadMerkleHasher.payloadRootFromPayload(redacted)).isEqualTo(before);
	}

	@Test
	void parseObject_acceptsSingleQuotedJson() {
		var payload = PayloadMerkleHasher.parseObject("{'name':'Alice','account':'12345'}");
		assertThat(payload.get("name").asString()).isEqualTo("Alice");
		assertThat(payload.get("account").asString()).isEqualTo("12345");
	}

	@Test
	void computeEventHash_usesCanonicalMillisecondTimestamp() {
		Instant timestamp = Instant.parse("2026-08-22T10:15:30.123456789Z");
		assertThat(PayloadMerkleHasher.formatTimestamp(timestamp)).isEqualTo("2026-08-22T10:15:30.123000Z");
		assertThat(PayloadMerkleHasher.formatTimestamp(Instant.parse("2026-08-22T10:15:30Z")))
				.isEqualTo("2026-08-22T10:15:30.000000Z");
		assertThat(PayloadMerkleHasher.formatTimestamp(null)).isEmpty();
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

	@Test
	void parseObject_blankOrNullBecomesEmptyObject() {
		assertThat(PayloadMerkleHasher.parseObject(null).isEmpty()).isTrue();
		assertThat(PayloadMerkleHasher.parseObject("  ").isEmpty()).isTrue();
	}

	@Test
	void parseObject_rejectsInvalidJson() {
		assertThatThrownBy(() -> PayloadMerkleHasher.parseObject("{not-json"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("valid JSON");
	}

	@Test
	void seal_skipsNullFieldsAndKeepsExistingSalts() {
		String sealed = PayloadMerkleHasher.seal("{\"name\":\"Alice\",\"skip\":null}");
		var node = PayloadMerkleHasher.parseObject(sealed);
		assertThat(node.get("skip").isNull()).isTrue();
		assertThat(PayloadMerkleHasher.nestedStringMap(node, PayloadMerkleHasher.SALTS_KEY)).containsOnlyKeys("name");

		String resealed = PayloadMerkleHasher.seal(sealed);
		assertThat(PayloadMerkleHasher.nestedStringMap(PayloadMerkleHasher.parseObject(resealed), PayloadMerkleHasher.SALTS_KEY)
				.get("name"))
				.isEqualTo(PayloadMerkleHasher.nestedStringMap(node, PayloadMerkleHasher.SALTS_KEY).get("name"));
	}

	@Test
	void redact_rejectsReservedOrMissingKeys() {
		String sealed = PayloadMerkleHasher.seal("{\"name\":\"Alice\"}");
		assertThatThrownBy(() -> PayloadMerkleHasher.redact(sealed, List.of("__salts")))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> PayloadMerkleHasher.redact(sealed, List.of("missing")))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void collectLeafHashes_usesStoredLeafWhenSaltMissingAndSkipsWhenLeafMissing() {
		String json = "{\"name\":\"Alice\",\"orphan\":null,\"__salts\":{\"name\":\"  \"},\"__leaves\":{\"name\":\"stored-leaf\"}}";
		Map<String, String> leaves = PayloadMerkleHasher.collectLeafHashes(json);
		assertThat(leaves).containsEntry("name", "stored-leaf").doesNotContainKey("orphan");
	}

	@Test
	void nestedStringMap_handlesNullObjectAndNonObjectMetadata() {
		assertThat(PayloadMerkleHasher.nestedStringMap(null, "__salts")).isEmpty();
		var object = PayloadMerkleHasher.parseObject("{\"__salts\":\"not-an-object\",\"n\":1,\"gone\":null}");
		assertThat(PayloadMerkleHasher.nestedStringMap(object, PayloadMerkleHasher.SALTS_KEY)).isEmpty();
		assertThat(PayloadMerkleHasher.fieldValue(null)).isEmpty();
		assertThat(PayloadMerkleHasher.fieldValue(object.get("gone"))).isEmpty();
		assertThat(PayloadMerkleHasher.fieldValue(object.get("n"))).isEqualTo("1");
		assertThat(PayloadMerkleHasher.seal("{\"name\":\"Alice\",\"__salts\":\"x\"}")).contains("__salts");
	}

	@Test
	void collectLeafHashes_whenSaltAbsentUsesStoredLeafOrSkips() {
		assertThat(PayloadMerkleHasher.collectLeafHashes("{\"name\":\"Alice\"}")).isEmpty();
	}

	@Test
	void writeJsonAcceptsObjectNode() {
		assertThat(PayloadMerkleHasher.writeJson(PayloadMerkleHasher.parseObject("{\"a\":1}"))).contains("a");
	}

	@Test
	void leafHashAndEventHashTreatNullsAsEmpty() {
		assertThat(PayloadMerkleHasher.leafHash(null, null, null)).isEqualTo(PayloadMerkleHasher.sha256(""));
		assertThat(PayloadMerkleHasher.computeEventHash(null, null, null, null, null, null, null))
				.isEqualTo(PayloadMerkleHasher.sha256("||||||"));
		assertThat(PayloadMerkleHasher.isReserved("__leaves")).isTrue();
		assertThat(PayloadMerkleHasher.isReserved("name")).isFalse();
		assertThat(PayloadMerkleHasher.writeJson(PayloadMerkleHasher.parseObject("{}"))).isEqualTo("{}");
		assertThat(PayloadMerkleHasher.sha256(null)).isEqualTo(PayloadMerkleHasher.sha256(""));
	}

	@Test
	void privateConstructorIsInvokedForCoverage() throws Exception {
		var constructor = PayloadMerkleHasher.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertThat(constructor.newInstance()).isNotNull();
	}
}
