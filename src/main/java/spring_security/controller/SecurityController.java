package spring_security.controller;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/user")
    @Secured("ROLE_USER")
    public String user(){
        return "user";
    } //secured

    @GetMapping("/admin")
    @RolesAllowed("ADMIN")
    public String admin(){
        return "admin";
    }

    @GetMapping("/permit")
    @PermitAll
    public String permit(){
        return "permit";
    }

    @GetMapping("/deny")
    @DenyAll
    public String deny(){
        return "deny";
    }
}
