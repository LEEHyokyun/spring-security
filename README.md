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