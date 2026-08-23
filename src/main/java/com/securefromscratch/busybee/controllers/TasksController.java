package com.securefromscratch.busybee.controllers;

import com.securefromscratch.busybee.storage.Task;
import com.securefromscratch.busybee.storage.TaskNotFoundException;
import com.securefromscratch.busybee.storage.TasksStorage;
import jakarta.validation.Valid;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.Transformer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@RestController
@CrossOrigin(origins = "null")
public class TasksController {
    private static final Logger LOGGER = LoggerFactory.getLogger(TasksController.class);

    @Autowired
    private TasksStorage m_tasks;

    // GET /tasks – returns all tasks (authenticated users only, enforced by SecurityConfig)
    @GetMapping("/tasks")
    public Collection<TaskOut> getTasks() {
        List<Task> allTasks = m_tasks.getAll();
        Transformer<Task, TaskOut> transformer = t -> TaskOut.fromTask((Task) t);
        return CollectionUtils.collect(allTasks, transformer);
    }

    /**
     * POST /done
     * Body: { "taskid": "<uuid>" }
     * Response: { "success": true }
     *
     * Authorization: only the task creator or a responsible user may mark a task done.
     * Returns 404 if taskid does not exist.
     */
    @PostMapping("/done")
    @PreAuthorize("@taskAuth.userAllowedToCloseTask(#request.taskid(), authentication)")
    public ResponseEntity<String> markTaskDone(@RequestBody DoneRequest request, Authentication authentication)
            throws IOException {
        UUID taskid = request.taskid();
        boolean wasAlreadyDone = m_tasks.markDone(taskid);   // throws TaskNotFoundException if not found
        LOGGER.info("event=task_done id={} by={}", taskid, authentication.getName());
        String status = wasAlreadyDone ? "already_done" : "done";
        return ResponseEntity.ok("{\"success\":true,\"status\":\"" + status + "\"}");
    }

    /**
     * POST /create
     * Body: { "name": "...", "desc": "...", "dueDate": "...", "dueTime": "...", "responsibilityOf": [...] }
     * Response: { "taskid": "<uuid>" }
     *
     * Authorization: TRIAL users may only create if they have no open tasks.
     * name  – validated by TaskName (OWASP SafeTypes BoundedWord, 1–50 chars)
     * desc  – validated by SafeDescription (Jsoup-cleaned, max 500 chars)
     * Cross-field: dueDate/dueTime must be in the future if provided.
     * Duplicate task name check.
     */
    @PostMapping("/create")
    @PreAuthorize("@taskAuth.isAuthorizedToCreate(authentication)")
    public ResponseEntity<String> create(@Valid @RequestBody CreateTaskRequest request,
                                         Authentication authentication) throws IOException {
        String username = authentication.getName();
        String name = request.name().toString();

        // Reject duplicate task name (case-insensitive)
        boolean duplicate = m_tasks.getAll().stream()
                .anyMatch(t -> t.name().equalsIgnoreCase(name));
        if (duplicate) {
            LOGGER.warn("event=task_duplicate_name name={}", name);
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("{\"error\":\"A task with that name already exists\"}");
        }

        UUID id;
        if (request.dueDate() == null) {
            id = m_tasks.add(name, request.desc().getValue(),
                    username, request.responsibilityOf());
        } else if (request.dueTime() == null) {
            id = m_tasks.add(name, request.desc().getValue(),
                    request.dueDate(), username, request.responsibilityOf());
        } else {
            id = m_tasks.add(name, request.desc().getValue(),
                    request.dueDate(), request.dueTime(), username, request.responsibilityOf());
        }

        LOGGER.info("event=task_created id={} owner={} name={}", id, username, name);
        return ResponseEntity.ok("{\"taskid\":\"" + id + "\"}");
    }
}
