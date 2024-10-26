package com.example.springsecurity.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {

    /*
        Method Authorization
        直接讲 authorization 应用到 method，endpoint 之上
        相关方法跟filter level一样
     */

    @GetMapping("/hello")
    @PreAuthorize("hasAuthority('read')")
    public String hello(){
        return "Hello";
    }
}
