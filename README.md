## 유의사항

일정 단게별로 초기화 후 재진행(멀티모듈로 구성하면 끝이 없어서 초기화 후 진행이 더 효율적임)

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

2025.12.03(CSRF token을 Servlet Request로 부터 추출) : da78b1a62cdc1207a22f961119d58db4ccdcbc9c
2025.12.03(java script 적용 - post 요청 시 토큰 포함) : d13e922fdd8bc020304ae5041dee79b56e2f79ef
2025.12.03(java script 적용 - withHttpOnlyFalse + csrf token handler) : 94d8c21a72e484a7034b4b6e562789a6eb8f5cd9
2025.12.03(same site) : 0897c10e5321c0bd77cb9712cdb9748c5f57c061

2025.12.04(requestMatchers API) : d416ef7a9cd13eaf1674f46a561cbe417b520a34
2025.12.04(WebExpressionAuthorizationManager) : a9266a552455cdd8274ea07c8fa554fd5f89c836
2025.12.04(WebExpressionAuthorizationManager/Bean) : e61c770d140070bad602a7d6116a818968b591be
2025.12.04(customized RequestMatchers) : 5726a9dd041bdd022ee4fe77125eaf8745349477
2025.12.04(다중 security filter chain 구성 및 security Matchers 적용) : ef1e3d69d6837539e8c9bb049cfe604524bee5fc
2025.12.04(EnableMethodSecurity + postAuthorize/preAuthorize) : 03f98b7e8aab07eee50f4eff26a7e6bb2aa5bb7d
2025.12.04(EnableMethodSecurity + postFilter/preFilter) : e32868e1b4be8cf5d16b7e20aaa3fa33788cf74c

2025.12.05(Secured/JSR-250 *요청기반(anyRequest.authenticated)이 있다면 더 우선순위 적용 유의) : d4d7e84f9616e5ba7733544fa312f6f1300511ed, 3174b27f520a9ac367152e0a21c72c5e99cfb76d
2025.12.05(cutomized 어노테이션) : 9f154108f28317f72e856ac01398f67e509f8e01
2025.12.05(빈객체 활용) : 041e83604490bc5f5119c93fa8f1bd1d883597bd
2025.12.05(정적자원요청에 대한 보안예외 - WebSecurityCustomizer) : e082c7c06ee5f86be75b69c86196bdff43ac5f89
2025.12.05(정적자원요청에 대한 보안예외 - permitAll) : 409cc13e20478bcc35d3b34f4c583365a12807b0
2025.12.05(계층권한구조 - RoleHierarhcy) : 0a1b5a5b39d14b97e2a4278ab9db9a59d4a2b1f1

2025.12.08(Customized Authorization Manager) : 2e43b6c44844f8e999c7876b2c3c4e09603b7400
2025.12.08(Customized Request Matcher Delegating Authorization Manager) : 2c9aa1e0a73a066f43acf55ba84646dea0f1db15

2025.12.09(Customized Pre/Post Authorize advice) : 4ead4769bff0ce626ccaba254c6521ea3fd45908
2025.12.09(single/multiple customized pointcut) : f09b3fc2ce756c80aabeccacfd8070e30ed356cf
2025.12.09(Customized Advisor/AOP/Interceptor/advice/pointcut) : f5da0b9bc94444db55c5cc504cca0d332906e514

2025.12.10(Event Publisher(기본/Customized)) :

[인증]
- 4371e2a2379f91d439cd2acb79a8a72dd30b7f0d
- 35f4e4cf35278cb30616f62aca019e3a74514fe8
- dcc9753cccf90e7abef28551c815fb827a859449
- ebb19cfc09294a16f137960c3425aa4d1b1c96ad

[인가]
- 7464a7cdf9cda29600fd859731da69903dad1e7a

2025.12.11(Servlet기반(프로그래밍 based) 인증처리) : 0decdc4b847e06b6af713d675a0034bdd0847be9

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