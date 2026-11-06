package com.wisebrains.iam.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.Map;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidation(MethodArgumentNotValidException exception) {
        String message = exception.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .orElse("Request validation failed");
        return ResponseEntity.badRequest().body(Map.of("error", message));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadRequest(IllegalArgumentException exception) {
        String message = exception.getMessage() == null ? "Invalid request" : exception.getMessage();
        HttpStatus status = message.endsWith("already exists")
                ? HttpStatus.CONFLICT
                : HttpStatus.NOT_FOUND;
        return ResponseEntity.status(status).body(Map.of("error", message));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, String>> handleDataIntegrityViolation() {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", "A resource with the same unique value already exists"));
    }
}
