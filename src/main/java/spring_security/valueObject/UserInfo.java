package spring_security.valueObject;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Getter
@AllArgsConstructor
public class UserInfo {
    private String username;
    private String password;
    private Collection<GrantedAuthority> authorities;
}
