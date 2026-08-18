package com.securefromscratch.busybee.safety;

import com.fasterxml.jackson.annotation.JsonCreator;
import io.swagger.v3.oas.annotations.media.Schema;
import org.owasp.safetypes.exception.TypeValidationException;

/**
 * Safe image filename value type.
 * Rejects path separators and any characters that could enable path traversal.
 * Only allows alphanumeric, underscore, hyphen, and a single dot (for extension).
 */
@Schema(type = "String", description = "Image filename – no path separators allowed")
public class ImageName {
    // Allowed: UUID prefix + underscore + original name, no path traversal chars
    private static final String SAFE_PATTERN = "[a-zA-Z0-9_\\-\\.]+";

    private final String name;

    @JsonCreator
    public ImageName(String value) throws TypeValidationException {
        if (value == null || value.isBlank()) {
            throw new TypeValidationException();
        }
        // Reject path separators (path traversal prevention)
        if (value.contains("/") || value.contains("\\") || value.contains("..")) {
            throw new TypeValidationException();
        }
        if (!value.matches(SAFE_PATTERN)) {
            throw new TypeValidationException();
        }
        this.name = value;
    }

    public String getName() { return name; }
}
