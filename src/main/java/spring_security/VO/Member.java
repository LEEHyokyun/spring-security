package spring_security.VO;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class Member {
    private String username;
    private String password;

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }
}
