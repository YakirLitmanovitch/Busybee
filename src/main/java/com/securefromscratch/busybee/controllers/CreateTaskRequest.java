package com.securefromscratch.busybee.controllers;

import com.securefromscratch.busybee.safety.SafeDescription;
import com.securefromscratch.busybee.safety.TaskName;
import jakarta.validation.constraints.AssertTrue;
import com.securefromscratch.busybee.safety.Username;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;

/**
 * Request body for POST /create.
 *
 * name    – TaskName (OWASP SafeTypes BoundedWord, 1–50 chars, no HTML)
 * desc    – SafeDescription (Jsoup-cleaned, max 500 chars, strips all HTML tags)
 * dueDate – optional due date
 * dueTime – optional due time (requires dueDate)
 * responsibilityOf – array of usernames responsible for the task
 */
public record CreateTaskRequest(
        TaskName name,
        SafeDescription desc,
        LocalDate dueDate,
        LocalTime dueTime,
        String[] responsibilityOf
) {
    /**
     * Cross-field validation: if dueDate (and optionally dueTime) is provided,
     * the resulting datetime must be strictly in the future.
     */
    @AssertTrue(message = "dueDate/dueTime must be in the future")
    public boolean isDueDateTimeInFuture() {
        if (dueDate == null) return true;  // no due date → always valid
        LocalDateTime deadline = (dueTime != null)
                ? LocalDateTime.of(dueDate, dueTime)
                : dueDate.atStartOfDay();
        return deadline.isAfter(LocalDateTime.now());
    }
}
