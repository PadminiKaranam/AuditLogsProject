package com.persistent.audit.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;

/**
 * Salted per-field (Merkle-lite) hashing. Salts and leaf hashes are stored
 * inside the payload JSON string so Event needs no extra columns.
 */
@Slf4j
public final class PayloadMerkleHasher {

	public static final String SALTS_KEY = "__salts";
	public static final String LEAVES_KEY = "__leaves";

	private static final DateTimeFormatter CANONICAL_TIMESTAMP_FORMATTER = 
        new DateTimeFormatterBuilder()
            .appendPattern("yyyy-MM-dd'T'HH:mm:ss.")
            .appendFraction(ChronoField.NANO_OF_SECOND, 6, 6, false)
            .appendPattern("'Z'")
            .toFormatter()
            .withZone(java.time.ZoneOffset.UTC);

	private static final JsonMapper MAPPER = JsonMapper.builder().build();
	private static final SecureRandom RANDOM = new SecureRandom();

	private PayloadMerkleHasher() {
	}

	public static String seal(String payloadJson) {
		ObjectNode object = parseObject(payloadJson);
		ObjectNode salts = metadataObject(object, SALTS_KEY);
		ObjectNode leaves = metadataObject(object, LEAVES_KEY);
		for (String key : dataKeys(object)) {
			JsonNode value = object.get(key);
			if (value == null || value.isNull() || salts.has(key)) {
				continue;
			}
			String salt = randomSalt();
			salts.put(key, salt);
			leaves.put(key, leafHash(key, fieldValue(value), salt));
		}
		if (!dataKeys(object).isEmpty()) {
			object.set(SALTS_KEY, salts);
			object.set(LEAVES_KEY, leaves);
		}
		return writeJson(object);
	}

	public static String redact(String payloadJson, List<String> keys) {
		ObjectNode object = parseObject(payloadJson);
		for (String key : keys) {
			if (isReserved(key) || !object.has(key)) {
				throw new IllegalArgumentException("payload does not contain field: " + key);
			}
			object.putNull(key);
		}
		return writeJson(object);
	}

	public static Map<String, String> collectLeafHashes(String payloadJson) {
		ObjectNode object = parseObject(payloadJson);
		Map<String, String> salts = nestedStringMap(object, SALTS_KEY);
		Map<String, String> leaves = nestedStringMap(object, LEAVES_KEY);
		Map<String, String> result = new TreeMap<>();
		for (String key : dataKeys(object)) {
			JsonNode value = object.get(key);
			String salt = salts.get(key);
			if (value == null || value.isNull() || salt == null || salt.isBlank()) {
				String storedLeaf = leaves.get(key);
				if (storedLeaf != null) {
					result.put(key, storedLeaf);
				}
			} else {
				result.put(key, leafHash(key, fieldValue(value), salt));
			}
		}
		return result;
	}

	public static String payloadRootFromPayload(String payloadJson) {
		return payloadRootHash(collectLeafHashes(payloadJson));
	}

	public static String payloadRootHash(Map<String, String> leafHashes) {
		Map<String, String> sorted = new TreeMap<>(leafHashes);
		StringBuilder combined = new StringBuilder();
		boolean first = true;
		for (String leafHash : sorted.values()) {
			if (!first) {
				combined.append('|');
			}
			combined.append(leafHash);
			first = false;
		}
		return sha256(combined.toString());
	}

	public static String leafHash(String key, String value, String salt) {
		return sha256(nullToEmpty(key) + nullToEmpty(value) + nullToEmpty(salt));
	}

	public static String computeEventHash(String eventType, String actorId, String resourceType, String resourceId,
			String payloadRootHash, Instant timestamp, String previousHash) {
		String canonical = nullToEmpty(eventType) + "|"
				+ nullToEmpty(actorId) + "|"
				+ nullToEmpty(resourceType) + "|"
				+ nullToEmpty(resourceId) + "|"
				+ nullToEmpty(payloadRootHash) + "|"
				+ formatTimestamp(timestamp) + "|"
				+ nullToEmpty(previousHash);
		return sha256(canonical);
	}
	
	public static String formatTimestamp(Instant timestamp) {
        if (timestamp == null) {
            return "";
        }
        // Truncate to milliseconds to handle database precision differences
        Instant truncated = timestamp.truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
        return truncated.atOffset(java.time.ZoneOffset.UTC)
                .format(CANONICAL_TIMESTAMP_FORMATTER);
    }

	public static ObjectNode parseObject(String payloadJson) {
		if (payloadJson == null || payloadJson.isBlank()) {
			return MAPPER.createObjectNode();
		}
		try {
			String normalizedJson = payloadJson.replace('\'', '"');
			JsonNode node = MAPPER.readTree(normalizedJson);
			if (node == null || !node.isObject()) {
				throw new IllegalArgumentException("payload must be a JSON object");
			}
			return (ObjectNode) node;
		} catch (JacksonException ex) {
			throw new IllegalArgumentException("payload must be valid JSON", ex);
		}
	}

	public static Map<String, String> nestedStringMap(ObjectNode object, String metadataKey) {
		Map<String, String> result = new TreeMap<>();
		if (object == null || !object.has(metadataKey) || !object.get(metadataKey).isObject()) {
			return result;
		}
		Iterator<Map.Entry<String, JsonNode>> fields = object.get(metadataKey).properties().iterator();
		while (fields.hasNext()) {
			Map.Entry<String, JsonNode> field = fields.next();
			result.put(field.getKey(), fieldValue(field.getValue()));
		}
		return result;
	}

	public static String writeJson(Object value) {
		try {
			return MAPPER.writeValueAsString(value);
		} catch (JacksonException ex) {
			throw new IllegalStateException("Unable to serialize JSON", ex);
		}
	}

	public static String fieldValue(JsonNode node) {
		if (node == null || node.isNull()) {
			return "";
		}
		if (node.isString()) {
			return node.asString();
		}
		return node.toString();
	}

	public static boolean isReserved(String key) {
		return SALTS_KEY.equals(key) || LEAVES_KEY.equals(key);
	}

	public static String sha256(String input) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashed = digest.digest(nullToEmpty(input).getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(hashed);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 is not available", e);
		}
	}

	private static ObjectNode metadataObject(ObjectNode object, String key) {
		if (object.has(key) && object.get(key).isObject()) {
			return (ObjectNode) object.get(key).deepCopy();
		}
		return MAPPER.createObjectNode();
	}

	private static List<String> dataKeys(ObjectNode object) {
		List<String> keys = new ArrayList<>();
		Iterator<Map.Entry<String, JsonNode>> fields = object.properties().iterator();
		while (fields.hasNext()) {
			String key = fields.next().getKey();
			if (!isReserved(key)) {
				keys.add(key);
			}
		}
		return keys;
	}

	private static String randomSalt() {
		byte[] bytes = new byte[16];
		RANDOM.nextBytes(bytes);
		return HexFormat.of().formatHex(bytes);
	}

	private static String nullToEmpty(String value) {
		return value == null ? "" : value;
	}
}
