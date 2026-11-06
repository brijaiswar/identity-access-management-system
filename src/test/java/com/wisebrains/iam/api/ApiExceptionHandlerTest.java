package com.wisebrains.iam.api;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.core.MethodParameter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.lang.reflect.Method;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ApiExceptionHandlerTest {
    private final ApiExceptionHandler handler = new ApiExceptionHandler();
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/register");

    @Test
    void mapsDuplicateResourcesToConflictProblemDetails() {
        var response = handler.handleDuplicate(
                new DuplicateResourceException("Email already exists"), request);

        assertEquals(409, response.getStatusCode().value());
        assertEquals("Email already exists", response.getBody().getDetail());
        assertEquals("about:blank", response.getBody().getType().toString());
        assertEquals("application/problem+json", response.getHeaders().getContentType().toString());
    }

    @Test
    void mapsInvalidArgumentsToBadRequestWithoutLeakingInternalMessage() {
        var response = handler.handleBadRequest(new IllegalArgumentException("internal detail"), request);

        assertEquals(400, response.getStatusCode().value());
        assertEquals("Invalid request", response.getBody().getDetail());
    }

    @Test
    void mapsMissingResourcesToNotFound() {
        var response = handler.handleResponseStatus(
                new org.springframework.web.server.ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"),
                request);

        assertEquals(404, response.getStatusCode().value());
        assertEquals("User not found", response.getBody().getDetail());
    }

    @Test
    void returnsStructuredValidationErrors() throws NoSuchMethodException {
        var target = new Object();
        var bindingResult = new BeanPropertyBindingResult(target, "request");
        bindingResult.addError(new FieldError("request", "username", "must not be blank"));
        Method method = ApiExceptionHandlerTest.class.getDeclaredMethod("returnsStructuredValidationErrors");
        var exception = new MethodArgumentNotValidException(new MethodParameter(method, -1), bindingResult);

        var response = handler.handleValidation(exception, request);

        assertEquals(400, response.getStatusCode().value());
        assertEquals("Request validation failed", response.getBody().getDetail());
        assertEquals(Map.of("username", "must not be blank"), response.getBody().getProperties().get("errors"));
    }
}
