package com.shieldgate.security.api.hello;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class hello {

    @GetMapping("/api/v1/hello/secure")
    public String secureHello() {
        return "Hello from a protected endpoint";
    }
}