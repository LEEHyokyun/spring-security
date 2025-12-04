package spring_security.service;

import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class SecurityService {
    @PreFilter("filterObject.owner == authentication.name")
    public List<String> write(List<String> data){
        //owner -> property로 정의되어야 한다.
        return data;
    }

    //map -> value객체에서 owner property 추출
//    @PreFilter("filterObject.value.owner == authentication.name")
//    public Map<String, Object> write(Map<String, Object> data){
//        //owner -> property로 정의되어야 한다.
//        return data;
//    }
}
