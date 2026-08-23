package com.securefromscratch.busybee.safety;

import com.fasterxml.jackson.annotation.JsonCreator;
import io.swagger.v3.oas.annotations.media.Schema;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.owasp.safetypes.exception.TypeValidationException;

@Schema(type = "String", description = "Task description – only safe HTML is kept (max 500 characters)")
public class SafeDescription {
    public static final int MAX_LENGTH = 500;

    private static final Safelist ALLOWED = Safelist.basicWithImages()
            .addTags("u")
            .preserveRelativeLinks(false);

    private final String value;

    @JsonCreator
    public SafeDescription(String raw) throws TypeValidationException {
        if (raw == null) throw new TypeValidationException();
        String cleaned = Jsoup.clean(raw, ALLOWED);
        if (cleaned.length() > MAX_LENGTH) throw new TypeValidationException();
        this.value = cleaned;
    }

    public String getValue() { return value; }

    @Override
    public String toString() { return value; }
}