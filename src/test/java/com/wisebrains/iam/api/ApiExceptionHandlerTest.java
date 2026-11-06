package com.wisebrains.iam.api;

import org.junit.jupiter.api.Test;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ApiExceptionHandlerTest {
    private final ApiExceptionHandler handler = new ApiExceptionHandler();

    @Test
    void returnsConflictForDuplicateResources() {
        var response = handler.handleBadRequest(new IllegalArgumentException("Email already exists"));

        assertEquals(409, response.getStatusCode().value());
        assertEquals("Email already exists", response.getBody().get("error"));
    }

    @Test
    void returnsNotFoundForMissingResources() {
        var response = handler.handleBadRequest(new IllegalArgumentException("User not found: alice"));

        assertEquals(404, response.getStatusCode().value());
    }

    @Test
    void returnsSafeMessageWhenExceptionHasNoMessage() {
        var response = handler.handleBadRequest(new IllegalArgumentException());

        assertEquals(404, response.getStatusCode().value());
        assertEquals("Invalid request", response.getBody().get("error"));
    }

    @Test
    void returnsFirstValidationError() throws NoSuchMethodException {
        var target = new Object();
        var bindingResult = new BeanPropertyBindingResult(target, "request");
        bindingResult.addError(new FieldError("request", "username", "must not be blank"));
        Method method = ApiExceptionHandlerTest.class.getDeclaredMethod("returnsFirstValidationError");
        var exception = new MethodArgumentNotValidException(new MethodParameter(method, -1), bindingResult);

        var response = handler.handleValidation(exception);

        assertEquals(400, response.getStatusCode().value());
        assertEquals("username: must not be blank", response.getBody().get("error"));
    }
}
