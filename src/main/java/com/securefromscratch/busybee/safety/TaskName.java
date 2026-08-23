package com.securefromscratch.busybee.safety;

import com.fasterxml.jackson.annotation.JsonCreator;
import io.swagger.v3.oas.annotations.media.Schema;
import org.owasp.safetypes.exception.TypeValidationException;
import org.owasp.safetypes.types.string.words.BoundedWord;

@Schema(type = "String", description = "Task name (1–50 characters, plain text, no HTML)")
public class TaskName extends BoundedWord {
    public static final int MIN_LENGTH = 1;
    public static final int MAX_LENGTH = 50;

    private final String value;

    @JsonCreator
    public TaskName(String value) throws TypeValidationException {
        super(value);
        this.value = value;
    }

    @Override
    public Integer min() { return MIN_LENGTH; }

    @Override
    public Integer max() { return MAX_LENGTH; }

    @Override
    public String toString() { return value; }
}