package com.securefromscratch.busybee.config;

import com.securefromscratch.busybee.safety.ImageName;
import org.owasp.safetypes.exception.TypeValidationException;
import org.springframework.context.annotation.Configuration;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Registers custom type converters so Spring MVC can bind SafeTypes
 * value objects directly from @RequestParam strings.
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addFormatters(FormatterRegistry registry) {
        // Converts "?img=<filename>" → ImageName (validates in constructor)
        registry.addConverter(String.class, ImageName.class, source -> {
            try {
                return new ImageName(source);
            } catch (TypeValidationException e) {
                throw new IllegalArgumentException("Invalid image name: " + source);
            }
        });
    }
}
