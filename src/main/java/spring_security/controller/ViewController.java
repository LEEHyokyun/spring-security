package spring_security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewController {
    @GetMapping("/form")
    public String form() {
        //thymeleaf
        //th:action="${/formCsrf}" -> POST mapping reuturns csrfToken
        //렌더링하면서 코드 생성
        return "form";
    }
}
