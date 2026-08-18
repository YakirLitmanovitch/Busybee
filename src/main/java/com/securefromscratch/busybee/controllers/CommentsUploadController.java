package com.securefromscratch.busybee.controllers;

import com.securefromscratch.busybee.storage.FileStorage;
import com.securefromscratch.busybee.storage.Task;
import com.securefromscratch.busybee.storage.TaskNotFoundException;
import com.securefromscratch.busybee.storage.TasksStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * POST /comment – add a comment (with optional file attachment) to a task.
 *
 * Multipart fields:
 *   taskid  – UUID of the task
 *   text    – comment text (plain text only, single line)
 *   replyTo – optional UUID of parent comment
 *   file    – optional image or attachment (validated by FileStorage)
 *
 * Security:
 *   - File size checked at route level (not just Spring's global limit)
 *   - Browser Content-Type validated against extension magic bytes
 *   - Comment text must be plain text (no HTML) and single-line
 *   - Filename validated by FileStorage (no path separators, UUID prefix)
 */
@RestController
public class CommentsUploadController {
    private static final Logger LOGGER = LoggerFactory.getLogger(CommentsUploadController.class);

    /** Maximum file size allowed per comment upload (5 MB) */
    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024L;

    private static final List<String> ALLOWED_IMAGE_EXTS = List.of("jpg", "jpeg", "png", "gif", "webp");
    private static final List<String> ALLOWED_ATTACH_EXTS = List.of("pdf", "docx");
    private static final List<String> ALL_ALLOWED = List.of("jpg", "jpeg", "png", "gif", "webp", "pdf", "docx");

    @Autowired private TasksStorage m_tasks;
    @Autowired private FileStorage  m_files;

    record CommentFields(UUID taskid, String text, UUID replyTo) {}

    @PostMapping("/comment")
    public ResponseEntity<String> addComment(
            @RequestParam("taskid") UUID taskid,
            @RequestParam("text") String text,
            @RequestParam(value = "replyTo", required = false) UUID replyTo,
            @RequestParam(value = "file", required = false) MultipartFile file,
            Authentication auth) {

        CommentFields fields = new CommentFields(taskid, text, replyTo);
        try {
            // 1. Validate comment text – plain text only, single line
            if (text == null || text.isBlank()) {
                throw new IllegalArgumentException("Comment text cannot be empty");
            }
            if (text.contains("<") || text.contains(">") || text.contains("&")) {
                throw new IllegalArgumentException("Comment text must be plain text, no HTML allowed");
            }
            if (text.contains("\n") || text.contains("\r")) {
                throw new IllegalArgumentException("Comment text must be a single line");
            }

            // 2. Find the task
            Task task = m_tasks.find(taskid)
                    .orElseThrow(() -> new TaskNotFoundException(taskid));

            // 3. Handle optional file upload
            Optional<String> imageRef      = Optional.empty();
            Optional<String> attachmentRef = Optional.empty();

            if (file != null && !file.isEmpty()) {
                // Route-level size check (before reading file content)
                if (file.getSize() > MAX_FILE_SIZE) {
                    throw new IllegalArgumentException("File exceeds maximum size of 5 MB");
                }

                String storedName = m_files.saveFile(file, ALL_ALLOWED);
                String ext = extension(file.getOriginalFilename());

                if (ALLOWED_IMAGE_EXTS.contains(ext)) {
                    imageRef = Optional.of(storedName);
                } else {
                    attachmentRef = Optional.of(storedName);
                }
            }

            // 4. Save comment
            m_tasks.addComment(task, text, imageRef, attachmentRef,
                    auth.getName(), Optional.ofNullable(replyTo));

            LOGGER.info("event=comment_added taskid={} by={} hasFile={}", fields.taskid(), auth.getName(), file != null && !file.isEmpty());
            return ResponseEntity.ok("{\"success\":true}");

        } catch (Exception ex) {
            LOGGER.warn("event=comment_upload_rejected taskid={} reason={}", fields.taskid(), ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("{\"error\":\"" + ex.getMessage() + "\"}");
        }
    }

    private static String extension(String filename) {
        if (filename == null) return "";
        int dot = filename.lastIndexOf('.');
        return (dot >= 0) ? filename.substring(dot + 1).toLowerCase() : "";
    }
}
