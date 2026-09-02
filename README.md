# BusyBee – Secure Task Management System

A Spring Boot task management application built with secure-by-design principles as part of a Cybersecurity Lab course.

## Tech Stack

- **Java 21** / **Spring Boot 3.3.4** / **Gradle 8.14.2**
- **OWASP SafeTypes** – type-safe input validation
- **Jsoup** – server-side XSS prevention
- **BCrypt** – password hashing
- **SLF4J** – structured logging

## Security Features

### Authentication (`/login`)
- Passwords stored as **BCrypt hashes** – never in plaintext
- Pre-populated users receive **random UUID-based passwords** at startup (logged once to console)
- Session cookie: `HttpOnly`, `Secure`, `SameSite=Strict`
- All HTTP requests redirected to HTTPS automatically

### Authorization (`/done`, `/create`, `/image`)
- Role-based access control via **`@PreAuthorize` + SpEL**
- `ADMIN` / `CREATOR` can create tasks freely; `TRIAL` only if they have no open task
- Only task owners and admins can mark a task done
- Image access restricted to task owners and assigned users

### Input Validation (`/create`)
- `TaskName` – OWASP `BoundedWord`, 1–50 chars, no HTML tags, single line
- `SafeDescription` – Jsoup-cleaned with allowlist (links, images, bold/italic/underline); XSS blocked
- `dueDate` / `dueTime` – Java types with future-date cross-field validation
- `responsibilityOf` – `Username[]` type with regex validation + existence check

### File Upload Security (`/comment`)
1. Disk space check (50 MB reserve)
2. Max file size – 5 MB (Spring config + route-level)
3. Extension whitelist – `jpg`, `jpeg`, `png`, `gif`, `webp`, `pdf`, `docx`
4. Magic bytes verification
5. Browser Content-Type validation
6. UUID-based stored filename (hides original name)
7. Path sandbox – file always resolved inside `/uploads`

### Image Serving (`/image`)
- Extension whitelist – only image types served
- Path sandbox via `FileStorage.resolveSafe()`
- Content-Type set from fixed per-extension map (never from user input)
- IDOR protection via `@PreAuthorize`

### HTTPS
- PKCS12 keystore (`busybee.p12`) – **not committed to Git**
- Keystore password read from `KEYSTORE_PASSWORD` environment variable
- TLS 1.2 and 1.3 only
- Mixed Content prevented: `baseUrl = ""` in frontend (relative URLs)

### CSRF Protection (Bonus)
- `CookieCsrfTokenRepository.withHttpOnlyFalse()` – JS reads `XSRF-TOKEN` cookie
- All POST requests (including `/login`) require `X-XSRF-TOKEN` header
- Token sent automatically via `sendPost()` in `helpers.js`

### Error Handling
- `GlobalExceptionsHandler` (`@ControllerAdvice`) – centralized exception-to-HTTP-status mapping
- No stack traces exposed to clients

## Running Locally

### Prerequisites
- Java 21
- A PKCS12 keystore file (`busybee.p12`) in `src/main/resources/`

### Environment Variable
```bash
export KEYSTORE_PASSWORD=your_keystore_password
```

### Run
```bash
./gradlew bootRun
```

The app starts on **https://localhost:8443**.  
Temporary passwords for pre-populated users (`admin`, `alice`, `bob`, `charlie`) are printed to the console on startup.

## Git Security

`.gitignore` prevents secrets from being committed:
```
*.p12
*.jks
*.pfx
.env
*.env
launch.json
.vscode/
```
