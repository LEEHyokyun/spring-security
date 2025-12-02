## 유의사항

일정 단게별로 초기화 후 재진행(멀티모듈로 구성하면 끝이 없어서 초기화 후 진행이 더 효율적임)

실무적으로 적용가능할 정도로 내용을 분리할 필요가 있을때 초기화 후 재정리 진행.

~ 2025.11.26 : 85bfcb7ae3ae5867c16fd7fabbd92a26258725fe 까지
2025.11.26(*SecurityContext/SecurityContextHolderFilter) : fe3aa6f2466a30a466730a6e1c549e0f323c1626부터 
2025.11.26(*Spring MVC의 엔드포인트를 활용하여 인증구현(Servlet 기반)) : 8581629fe50dec7938d405d742ad93d0691577bb

2025.11.30(*동시세션방지 정책) : 35799d83381f62f628d636a5db841d26deb770d3

2025.12.01(*고정세션공격방지) : 128119eb4beec116f05db43383f069a50a5c45d7
2025.12.01(*session생성정책) : 3a9737fc832d33785132d616fde92ed41a6472a9
2025.12.01(*session information service) : f32203567214d5883a86e25870a95e1a3a2dea30
2025.12.01(*authenticationException/accessDeniedException) : 55aaa01cea54e04bb16540a2825dd5ab0751421c

2025.12.02(CorsConfiguration) : 93692f4904d3b3af41636e88bfc538d51b510006
2025.12.02(CSRF 적용) : d2cd253a87125a63bdc78fea3e7621ef31918837

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