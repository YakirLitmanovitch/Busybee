package com.securefromscratch.busybee.safety;

import com.fasterxml.jackson.annotation.JsonCreator;
import io.swagger.v3.oas.annotations.media.Schema;
import org.owasp.safetypes.exception.TypeValidationException;

@Schema(type = "String", description = "Password (8–64 chars, must include uppercase, lowercase, digit, special char)")
public class Password {
    public static final int MIN_LENGTH = 8;
    public static final int MAX_LENGTH = 64;

    private final String value;

    @JsonCreator
    public Password(String value) throws TypeValidationException {
        if (value == null || value.length() < MIN_LENGTH || value.length() > MAX_LENGTH) {
            throw new TypeValidationException();
        }
        // Must have: uppercase, lowercase, digit, special character
        if (!value.matches(".*[A-Z].*")
                || !value.matches(".*[a-z].*")
                || !value.matches(".*[0-9].*")
                || !value.matches(".*[^a-zA-Z0-9].*")) {
            throw new TypeValidationException();
        }
        this.value = value;
    }

    public String getValue() { return value; }
}
