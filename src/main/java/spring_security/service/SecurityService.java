package spring_security.service;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import spring_security.VO.Account;

@Service
public class SecurityService {
    @PreAuthorize(value = "''")
    public String getUser(){
        return "user";
    }

    @PostAuthorize(value = "''")
    public Account getOwner(String name){
        return new Account(name, false);
    }
}
