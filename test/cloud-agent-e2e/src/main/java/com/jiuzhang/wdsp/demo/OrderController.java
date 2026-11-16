package com.jiuzhang.wdsp.demo;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class OrderController {
    private final RestTemplate restTemplate = new RestTemplate();

    @PostMapping("/orders")
    public Map<String, Object> create(@RequestBody Map<String, String> request) {
        return restTemplate.postForObject("http://127.0.0.1:18081/profiles/42", request, Map.class);
    }

    @GetMapping("/profiles/{id}")
    public Map<String, Object> profile(@PathVariable String id) {
        return Map.of("id", id, "status", "ok");
    }

    @PostMapping("/profiles/{id}")
    public Map<String, Object> updateProfile(@PathVariable String id, @RequestBody Map<String, String> request) {
        return Map.of("id", id, "mobile", request.getOrDefault("mobile", ""), "status", "ok");
    }
}
