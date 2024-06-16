package com.cjmobileapps.security.demo

import org.springframework.http.ResponseEntity
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/demo-controller")
class DemoController {

    @GetMapping
    fun sayHello(): ResponseEntity<String> {
        println("SecurityContextHolder.getContext().authentication " + SecurityContextHolder.getContext().authentication)
        return ResponseEntity.ok("Hello from secured endpoint")
    }
}
