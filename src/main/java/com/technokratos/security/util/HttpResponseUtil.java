package com.technokratos.security.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.experimental.UtilityClass;
import org.springframework.http.MediaType;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@UtilityClass
public class HttpResponseUtil {

    public static void putExceptionInResponse(HttpServletRequest request, HttpServletResponse response,
                                              Exception exception, int exceptionStatus) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(exceptionStatus);

        ErrorDetails errorDetails = new ErrorDetails(exceptionStatus, "unauthorized",
                exception.getMessage(), request.getRequestURI());

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), errorDetails);
    }

    @Data
    @AllArgsConstructor
    private static class ErrorDetails {
        private int status;
        private String error;
        private String message;
        private String path;
    }
}
