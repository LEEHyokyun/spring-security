package spring_security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import spring_security.meta.RequireOwnership;
import spring_security.meta.isAdmin;

@RestController
public class SecurityController {

    @GetMapping("/admin")
    @isAdmin
    public String admin() {
        return "admin";
    }

    @GetMapping("/owner")
    @RequireOwnership
    public String owner(Long id) {
        return "owner";
    }
}
