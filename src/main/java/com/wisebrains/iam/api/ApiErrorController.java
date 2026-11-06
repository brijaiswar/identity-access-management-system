package com.wisebrains.iam.api;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
public class ApiErrorController implements ErrorController {
    @RequestMapping("/error")
    public ResponseEntity<ProblemDetail> handleError(HttpServletRequest request) {
        Object statusAttribute = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        int statusValue = statusAttribute instanceof Number number ? number.intValue() : 500;
        if (statusValue < 400 || statusValue > 599) {
            statusValue = 500;
        }

        HttpStatusCode status = HttpStatusCode.valueOf(statusValue);
        HttpStatus knownStatus = HttpStatus.resolve(statusValue);
        String title = knownStatus == null ? "HTTP Error" : knownStatus.getReasonPhrase();
        String detail = statusValue >= 500 ? "An unexpected server error occurred"
                : statusValue == 404 ? "Resource not found" : "The request could not be processed";
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setTitle(title);
        Object originalUri = request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);
        problem.setInstance(URI.create(originalUri instanceof String uri ? uri : request.getRequestURI()));
        return ResponseEntity.status(status)
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }
}
