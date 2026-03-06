package com.shieldgate.security.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class HelloController {

    @GetMapping("/api/v1/hello")
    public Map<String, Object> hello(@RequestParam(defaultValue = "Scott") String name) {

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("service", "shieldgate-security-api");
        response.put("message", "Hello " + name);

        return response;
    }
}