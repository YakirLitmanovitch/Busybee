package com.securefromscratch.busybee.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Handles secure file storage for uploaded images and attachments.
 *
 * Security measures:
 * 1. Filename validation – rejects names with path separators / null bytes
 * 2. Extension whitelist  – only allowed extensions are accepted
 * 3. Magic bytes check    – verifies actual file content matches declared extension
 * 4. Browser content-type – cross-checks MIME type sent by the browser
 * 5. UUID-based stored name – prevents filename collisions and hides original names
 * 6. Disk space check     – refuses upload if insufficient space remains
 * 7. Path sandbox         – stored file is always resolved inside the uploads directory
 */
@Service
public class FileStorage {
    private static final Logger LOGGER = LoggerFactory.getLogger(FileStorage.class);

    private static final Path UPLOAD_DIR = Paths.get("uploads").toAbsolutePath();
    private static final long MIN_FREE_BYTES = 50 * 1024 * 1024L; // 50 MB reserve

    /** Maps extension → first magic bytes (hex) */
    private static final Map<String, byte[]> MAGIC = Map.of(
            "jpg",  new byte[]{(byte)0xFF,(byte)0xD8,(byte)0xFF},
            "jpeg", new byte[]{(byte)0xFF,(byte)0xD8,(byte)0xFF},
            "png",  new byte[]{(byte)0x89, 0x50, 0x4E, 0x47},
            "gif",  new byte[]{0x47, 0x49, 0x46, 0x38},
            "webp", new byte[]{0x52, 0x49, 0x46, 0x46},   // RIFF header
            "pdf",  new byte[]{0x25, 0x50, 0x44, 0x46},   // %PDF
            "docx", new byte[]{0x50, 0x4B, 0x03, 0x04}    // ZIP (OOXML)
    );

    /** Maps extension → accepted browser MIME types */
    private static final Map<String, List<String>> MIME_MAP = Map.of(
            "jpg",  List.of("image/jpeg"),
            "jpeg", List.of("image/jpeg"),
            "png",  List.of("image/png"),
            "gif",  List.of("image/gif"),
            "webp", List.of("image/webp"),
            "pdf",  List.of("application/pdf"),
            "docx", List.of("application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            "application/zip")
    );

    /**
     * Saves a file after running all security checks.
     *
     * @param file             Uploaded multipart file
     * @param allowedExtensions Whitelist of acceptable extensions (lowercase, no dot)
     * @return UUID-prefixed stored filename (safe to embed in URLs)
     * @throws IOException              on I/O failure
     * @throws IllegalArgumentException on any security rejection
     */
    public String saveFile(MultipartFile file, List<String> allowedExtensions) throws IOException {
        String originalName = file.getOriginalFilename();

        // 1. Filename sanity
        if (originalName == null || originalName.isBlank()
                || originalName.contains("/") || originalName.contains("\\")
                || originalName.contains("\0") || originalName.contains("..")) {
            LOGGER.warn("event=file_rejected reason=filename_invalid originalName={}", originalName);
            throw new IllegalArgumentException("Invalid filename");
        }

        // 2. Extension whitelist
        String extension = extension(originalName).toLowerCase();
        if (!allowedExtensions.contains(extension)) {
            LOGGER.warn("event=file_rejected reason=extension_not_allowed ext={}", extension);
            throw new IllegalArgumentException("File type not allowed: " + extension);
        }

        // 3. Disk space
        long usable = UPLOAD_DIR.toFile().getUsableSpace();
        long size   = file.getSize();
        if (usable - size < MIN_FREE_BYTES) {
            LOGGER.warn("event=file_rejected reason=insufficient_disk_space available={} required={}", usable, size);
            throw new IllegalArgumentException("Insufficient disk space");
        }

        // 4. Magic bytes
        byte[] expected = MAGIC.get(extension);
        if (expected != null) {
            try (InputStream in = file.getInputStream()) {
                byte[] header = in.readNBytes(expected.length);
                if (!startsWith(header, expected)) {
                    LOGGER.warn("event=file_rejected reason=magic_bytes_mismatch ext={}", extension);
                    throw new IllegalArgumentException("File content does not match declared extension");
                }
            }
        }

        // 5. Browser content-type
        String browserMime = file.getContentType();
        List<String> acceptedMimes = MIME_MAP.get(extension);
        if (acceptedMimes != null && (browserMime == null || !acceptedMimes.contains(browserMime))) {
            LOGGER.warn("event=file_rejected reason=content_type_mismatch mime={}", browserMime);
            throw new IllegalArgumentException("Content-Type not accepted: " + browserMime);
        }

        // 6. UUID-based stored name (path-safe, collision-resistant)
        String storedFilename = UUID.randomUUID() + "_" + sanitize(originalName);

        // 7. Path sandbox – resolve inside upload dir, prevent traversal
        Files.createDirectories(UPLOAD_DIR);
        Path target = UPLOAD_DIR.resolve(storedFilename).normalize();
        if (!target.startsWith(UPLOAD_DIR)) {
            // Should be impossible given UUID prefix, but defense-in-depth
            throw new SecurityException("Path traversal detected");
        }

        file.transferTo(target);
        LOGGER.info("event=file_stored storedName={} size={}", storedFilename, file.getSize());
        return storedFilename;
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static String extension(String filename) {
        int dot = filename.lastIndexOf('.');
        return (dot >= 0 && dot < filename.length() - 1) ? filename.substring(dot + 1) : "";
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) return false;
        }
        return true;
    }

    /** Keep only safe filename characters (removes spaces, special chars). */
    private static String sanitize(String name) {
        return name.replaceAll("[^a-zA-Z0-9._\\-]", "_");
    }

    public Path resolveSafe(String filename) {
        Path resolved = UPLOAD_DIR.resolve(filename).normalize();
        if (!resolved.startsWith(UPLOAD_DIR)) {
            throw new SecurityException("Path traversal attempt detected");
        }
        return resolved;
    }
}
