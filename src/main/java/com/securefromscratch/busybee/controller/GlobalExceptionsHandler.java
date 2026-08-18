package com.securefromscratch.busybee.controller;

import com.securefromscratch.busybee.storage.TaskNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

/**
 * Centralised exception handler – all unhandled exceptions land here.
 * Returns clean JSON errors; never leaks stack traces to the client.
 */
@ControllerAdvice
public class GlobalExceptionsHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalExceptionsHandler.class);

    /** Task not found → 404 */
    @ExceptionHandler(TaskNotFoundException.class)
    public ResponseEntity<String> handleTaskNotFound(TaskNotFoundException ex, HttpServletRequest req) {
        LOGGER.warn("event=resource_missing code=TASK_NOT_FOUND endpoint={}", req.getRequestURI());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body("{\"error\":\"Task not found\"}");
    }

    /** Bean Validation failures (@Valid on request body) → 400 */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<String> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest req) {
        String message = ex.getBindingResult().getAllErrors().get(0).getDefaultMessage();
        LOGGER.warn("event=validation_error endpoint={} message={}", req.getRequestURI(), message);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("{\"error\":\"" + message + "\"}");
    }

    /** SafeTypes TypeValidationException / IllegalArgumentException → 400 */
    @ExceptionHandler({IllegalArgumentException.class,
                       org.owasp.safetypes.exception.TypeValidationException.class})
    public ResponseEntity<String> handleValidationError(Exception ex, HttpServletRequest req) {
        LOGGER.warn("event=validation_error endpoint={} message={}", req.getRequestURI(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("{\"error\":\"Invalid input\"}");
    }

    /** File upload too large → 413 */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<String> handleUploadTooLarge(MaxUploadSizeExceededException ex, HttpServletRequest req) {
        LOGGER.warn("event=upload_error endpoint={} message={}", req.getRequestURI(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .body("{\"error\":\"Uploaded file is too large\"}");
    }

    /** @PreAuthorize failure → 403 */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> handleAccessDenied(AccessDeniedException ex, HttpServletRequest req) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String user = (auth != null) ? auth.getName() : "anonymous";
        LOGGER.warn("event=access_denied user={} endpoint={}", user, req.getRequestURI());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body("{\"error\":\"Access denied\"}");
    }

    /** Catch-all – unexpected errors → 500 (never leak details) */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleUnexpected(Exception ex, HttpServletRequest req) {
        LOGGER.error("event=unexpected_error endpoint={}", req.getRequestURI(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("{\"error\":\"An unexpected error occurred\"}");
    }
}
