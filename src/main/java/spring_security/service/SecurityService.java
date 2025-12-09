package spring_security.service;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import spring_security.VO.Account;

@Service
public class SecurityService {

    public String getUser(){
        return "user";
    }

    public Account getOwner(String name){
        return new Account(name, false);
    }
}
