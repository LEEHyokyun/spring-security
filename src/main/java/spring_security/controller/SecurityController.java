package spring_security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import spring_security.VO.Account;
import spring_security.service.SecurityService;

@RestController
@RequiredArgsConstructor
public class SecurityController {
    private final SecurityService securityService;

    @GetMapping("/user")
    public String user(){
        return securityService.getUser();
    }

    @GetMapping("/owner")
    public Account owner(@RequestBody Account account){
        return securityService.getOwner(account.getOwner());
    }
}
