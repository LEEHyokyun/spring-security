package spring_security.customized;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
}
