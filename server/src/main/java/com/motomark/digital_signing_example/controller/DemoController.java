package com.motomark.digital_signing_example.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @GetMapping("/secure-data")
    public String secure(@AuthenticationPrincipal String principal) {
        return "Hello, signed client: " + principal;
    }
}
