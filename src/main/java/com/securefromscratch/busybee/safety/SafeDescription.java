package com.securefromscratch.busybee.safety;

import com.fasterxml.jackson.annotation.JsonCreator;
import io.swagger.v3.oas.annotations.media.Schema;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.owasp.safetypes.exception.TypeValidationException;

/**
 * XSS-safe description field.
 * Uses Jsoup with Safelist.none() to strip ALL HTML tags, preventing XSS.
 * Unlike regex-based approaches, Jsoup correctly handles nested/obfuscated HTML.
 */
@Schema(type = "String", description = "Task description – HTML is stripped automatically (max 500 characters)")
public class SafeDescription {
    public static final int MAX_LENGTH = 500;

    private final String value;

    @JsonCreator
    public SafeDescription(String raw) throws TypeValidationException {
        if (raw == null) {
            throw new TypeValidationException();
        }
        // Strip ALL HTML – Jsoup Safelist.none() allows no tags at all
        String cleaned = Jsoup.clean(raw, Safelist.none());
        if (cleaned.length() > MAX_LENGTH) {
            throw new TypeValidationException();
        }
        this.value = cleaned;
    }

    public String getValue() { return value; }
}
