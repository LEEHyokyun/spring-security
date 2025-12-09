package spring_security.VO;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
public class Account {
    private String owner;
    private boolean isSecured;

    public String getOwner() {
        return this.owner;
    }

    public boolean isSecured() {
        return this.isSecured;
    }
}
