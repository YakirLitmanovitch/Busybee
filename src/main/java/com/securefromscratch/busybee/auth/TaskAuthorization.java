package com.securefromscratch.busybee.auth;

import com.securefromscratch.busybee.safety.ImageName;
import com.securefromscratch.busybee.storage.Task;
import com.securefromscratch.busybee.storage.TasksStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

/**
 * Authorization rules called from @PreAuthorize SpEL expressions, e.g.:
 *   @PreAuthorize("@taskAuth.userAllowedToCloseTask(#taskid, authentication)")
 */
@Component("taskAuth")
public class TaskAuthorization {
    private static final Logger LOGGER = LoggerFactory.getLogger(TaskAuthorization.class);

    @Autowired private TasksStorage m_tasks;

    /**
     * Only the task creator or someone in responsibilityOf may close (mark done) a task.
     */
    public boolean userAllowedToCloseTask(UUID taskid, Authentication auth) {
        String user = auth.getName();
        Optional<Task> taskOpt = m_tasks.find(taskid);
        if (taskOpt.isEmpty()) return false;
        Task task = taskOpt.get();
        boolean allowed = task.createdBy().equals(user)
                || Arrays.asList(task.responsibilityOf()).contains(user);
        if (!allowed) {
            LOGGER.warn("event=authorization_denied action=close_task taskid={} user={}", taskid, user);
        }
        return allowed;
    }

    /**
     * TRIAL users may only create a task when they have no currently open tasks.
     * CREATOR and ADMIN can always create.
     */
    public boolean isAuthorizedToCreate(Authentication auth) {
        String user = auth.getName();
        boolean isTrial = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_TRIAL"));
        if (!isTrial) return true;

        boolean hasOpenTask = m_tasks.getAll().stream()
                .anyMatch(t -> t.createdBy().equals(user) && !t.done());
        if (hasOpenTask) {
            LOGGER.warn("event=authorization_denied action=create_task user={} reason=trial_has_open_task", user);
            return false;
        }
        return true;
    }

    /**
     * A user may view an image only if it is attached to a task they own or are responsible for.
     */
    public boolean imgIsInOwnedOrAssignedTask(ImageName imgName, Authentication auth) {
        String user = auth.getName();
        boolean allowed = m_tasks.getAll().stream()
                .filter(t -> t.createdBy().equals(user) || Arrays.asList(t.responsibilityOf()).contains(user))
                .flatMap(t -> t.comments().stream())
                .anyMatch(c -> c.image().map(img -> img.equals(imgName.getName())).orElse(false)
                        || c.attachment().map(att -> att.equals(imgName.getName())).orElse(false));
        if (!allowed) {
            LOGGER.warn("event=authorization_denied action=view_image img={} user={}", imgName.getName(), user);
        }
        return allowed;
    }
}
