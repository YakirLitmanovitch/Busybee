package com.securefromscratch.busybee.safety;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SafeDescriptionTest {

    @Test
    void blocksScriptTag() throws Exception {
        SafeDescription desc = new SafeDescription("<script>alert('xss')</script>Hello");
        assertFalse(desc.getValue().contains("<script>"));
        assertTrue(desc.getValue().contains("Hello"));
    }

    @Test
    void blocksJavascriptHref() throws Exception {
        SafeDescription desc = new SafeDescription("<a href=\"javascript:alert(1)\">click</a>");
        assertFalse(desc.getValue().contains("javascript:"));
    }

    @Test
    void blocksOnErrorAttribute() throws Exception {
        SafeDescription desc = new SafeDescription("<img src=x onerror=alert(1)>");
        assertFalse(desc.getValue().contains("onerror"));
    }

    @Test
    void allowsSafeLink() throws Exception {
        SafeDescription desc = new SafeDescription("<a href=\"https://example.com\">link</a>");
        assertTrue(desc.getValue().contains("<a"));
        assertTrue(desc.getValue().contains("href"));
    }

    @Test
    void allowsImage() throws Exception {
        SafeDescription desc = new SafeDescription("<img src=\"https://example.com/img.png\">");
        assertTrue(desc.getValue().contains("<img"));
    }

    @Test
    void allowsBoldItalicUnderline() throws Exception {
        SafeDescription desc = new SafeDescription("<b>bold</b> <i>italic</i> <u>underline</u>");
        assertTrue(desc.getValue().contains("<b>"));
        assertTrue(desc.getValue().contains("<i>"));
        assertTrue(desc.getValue().contains("<u>"));
    }
}