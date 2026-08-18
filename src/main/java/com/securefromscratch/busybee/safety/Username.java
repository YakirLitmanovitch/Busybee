package com.securefromscratch.busybee.safety;

import com.fasterxml.jackson.annotation.JsonCreator;
import io.swagger.v3.oas.annotations.media.Schema;
import org.owasp.safetypes.exception.TypeValidationException;
import org.owasp.safetypes.types.string.words.BoundedWord;

@Schema(type = "String", description = "Username (3–20 characters, alphanumeric/underscore only)")
public class Username extends BoundedWord {
    public static final int MIN_LENGTH = 3;
    public static final int MAX_LENGTH = 20;

    @JsonCreator
    public Username(String value) throws TypeValidationException {
        super(value);
        if (!value.matches("[a-zA-Z0-9_]+")) {
            throw new TypeValidationException();
        }
    }

    @Override
    public Integer min() { return MIN_LENGTH; }

    @Override
    public Integer max() { return MAX_LENGTH; }
}
