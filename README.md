## 유의사항

일정 단게별로 초기화 후 재진행(멀티모듈로 구성하면 끝이 없어서 초기화 후 진행이 더 효율적임)

실무적으로 적용가능할 정도로 내용을 분리할 필요가 있을때 초기화 후 재정리 진행.

~ 2025.11.26 : 85bfcb7ae3ae5867c16fd7fabbd92a26258725fe 까지
2025.11.26(*SecurityContext/SecurityContextHolderFilter) : fe3aa6f2466a30a466730a6e1c549e0f323c1626부터 
2025.11.26(*Spring MVC의 엔드포인트를 활용하여 인증구현(Servlet 기반)) : 8581629fe50dec7938d405d742ad93d0691577bb

## 0. Duty

FilterChain의 동작은
- application run
- 실제 동작(요청 시)

모두 일단 디버깅모드에서 확인하라.

하이젠 버그가 너무 많은데 프레임워크 레벨이라서 수정이 불가능하기에 디버깅모드로 선제확인 필요.

## 1. authenticationManager(ProviderManager) 객체 생성?

> 이미 Provider는 애플리케이션 런타임 시점에 생성이 되었다.

- httpBuilder를 통한 객체 생성 ? Provider는 이미 생성, ProviderManager만 생성하겠다.
- 직접 생성 ? Provider, ProviderManager 모두 직접 생성하겠다.