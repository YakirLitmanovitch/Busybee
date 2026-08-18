package com.securefromscratch.busybee.controllers;

import java.util.UUID;

/**
 * Request body for POST /done.
 * taskid must be a valid UUID – Jackson will reject invalid UUIDs automatically.
 */
public record DoneRequest(UUID taskid) {}
