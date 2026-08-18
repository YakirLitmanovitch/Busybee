package com.securefromscratch.busybee.controllers;

import com.securefromscratch.busybee.safety.ImageName;
import com.securefromscratch.busybee.storage.FileStorage;
import org.owasp.safetypes.exception.TypeValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * GET /image?img=<filename>
 *
 * Serves uploaded images. Security:
 *   - ImageName value type rejects any path-traversal characters
 *   - Extension whitelist – only image types served from this endpoint
 *   - PathSandbox via FileStorage.resolveSafe() – ensures file stays in uploads dir
 *   - IDOR protection via @PreAuthorize – user must own/be assigned a task that references this image
 */
@RestController
public class ImageController {
    private static final Logger LOGGER = LoggerFactory.getLogger(ImageController.class);

    private static final List<String> ALLOWED_EXTENSIONS = List.of("jpg", "jpeg", "png", "gif", "webp");

    private static final Map<String, MediaType> MEDIA_TYPES = Map.of(
            "jpg",  MediaType.IMAGE_JPEG,
            "jpeg", MediaType.IMAGE_JPEG,
            "png",  MediaType.IMAGE_PNG,
            "gif",  MediaType.IMAGE_GIF,
            "webp", MediaType.parseMediaType("image/webp")
    );

    @Autowired
    private FileStorage m_files;

    @GetMapping("/image")
    @PreAuthorize("@taskAuth.imgIsInOwnedOrAssignedTask(#img, authentication)")
    public ResponseEntity<byte[]> getImage(@RequestParam("img") ImageName img,
                                           Authentication auth) throws IOException {
        LOGGER.info("event=image_requested img={} by={}", img.getName(), auth.getName());

        // Extension whitelist check
        String ext = extension(img.getName());
        if (!ALLOWED_EXTENSIONS.contains(ext)) {
            LOGGER.warn("event=image_ext_rejected img={} ext={}", img.getName(), ext);
            return ResponseEntity.badRequest().build();
        }

        // Resolve file inside upload sandbox (path traversal protection)
        Path filePath = m_files.resolveSafe(img.getName());
        if (!Files.exists(filePath)) {
            LOGGER.warn("event=image_not_found img={}", img.getName());
            return ResponseEntity.notFound().build();
        }

        byte[] data = Files.readAllBytes(filePath);
        MediaType mediaType = MEDIA_TYPES.getOrDefault(ext, MediaType.APPLICATION_OCTET_STREAM);
        return ResponseEntity.ok().contentType(mediaType).body(data);
    }

    private static String extension(String filename) {
        int dot = filename.lastIndexOf('.');
        return (dot >= 0) ? filename.substring(dot + 1).toLowerCase() : "";
    }
}
