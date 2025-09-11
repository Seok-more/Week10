Brand new pintos for Operating Systems and Lab (CS330), KAIST, by Youngjin Kwon.

The manual is available at https://casys-kaist.github.io/pintos-kaist/.

---

pintos -- -q run alarm-multiple

jungle@a6412c5c73e2:/workspaces/pintos_22.04_lab_docker/pintos/threads/build$ 
make tests/threads/priority-donate-chain.result

## **얼마나 많은     코드를 작성해야 하나요?**
- 참고 솔루션에서 `git diff --stat`로 계산한 결과:
    - **총 330줄 추가, 12줄 삭제**
    - 주로 수정/추가하는 파일:
        - `devices/timer.c` : Alarm Clock 등 타이머 관련 로직 (29줄 추가)
        - `include/threads/fixed-point.h` : 고정소수점 연산 라이브러리(새 파일, 10줄 추가)
        - `include/threads/synch.h` : 동기화 헤더(4줄 추가)
        - `include/threads/thread.h` : 스레드 헤더(21줄 추가)
        - `threads/synch.c` : 동기화 구현(143줄 추가/수정)
        - `threads/thread.c` : 스레드 구현(135줄 추가/수정)
    - **fixed-point.h**는 새로 추가하는 파일.
    - 참고 솔루션은 여러 가지 중 하나일 뿐이며, 여러분의 코드가 꼭 모든 파일을 동일하게 수정할 필요는 없다.

---

## **새 소스 파일을 추가할 때 Makefile은 어떻게 수정하나요?**
- `.c` 파일을 추가할 때는 해당 디렉토리의 `targets.mk`에서 `dir_SRC` 변수에 파일 이름을 추가.
    - 예: `threads_SRC += fixed-point.c`
- 추가 후 `make` 실행.
- 새 `.h` 파일은 Makefile 수정 필요 없음.

---

## **warning: no previous prototype for func 의미**
- static이 아닌 함수의 선언부(프로토타입)가 헤더에 없을 때 발생.
- 해결법:
    - 헤더 파일에 프로토타입 추가.
    - 만약 외부에서 안 쓴다면 `static`으로 변경.

---

## **타이머 인터럽트 간격은?**
- 초당 `TIMER_FREQ`번 발생.
- 기본값: 100Hz (`devices/timer.h`)
- 값 바꾸지 말 것(테스트 실패 위험).

---

## **타임슬라이스 길이는?**
- 한 타임슬라이스는 `TIME_SLICE` 틱 (기본 4, `threads/thread.c`에서 선언)
- 값 바꾸지 말 것(테스트 실패 위험).

---

## **테스트 실행 방법**
- "Testing" 섹션 참고.

---

## **pass() 테스트 실패 원인?**
- 백트레이스에 pass()가 찍혀도 실제로는 fail()에서 panic이 발생한 것.
- GCC가 debug_panic()이 반환하지 않는 함수임을 알기 때문에, 리턴 주소가 pass()처럼 보임.
- 자세한 건 "Backtraces" 참고.

---

## **schedule() 후 인터럽트 재활성화는 어떻게?**
- schedule() 진입 경로는 모두 인터럽트 off.
- 다음 스레드가 실행될 때 각 경로에서 인터럽트 on:
    - thread_exit(): 해당 스레드로 다시 전환되지 않음.
    - thread_yield(): 복귀 시 인터럽트 복구.
    - thread_block(): 여러 곳에서 호출됨.
        - sema_down(): schedule() 복귀 시 인터럽트 복구.
        - idle(): 명시적으로 어셈블리 STI(인터럽트 on).
        - wait() in devices/intq.c: 호출자가 직접 복구.
    - 새로 생성된 스레드는 kernel_thread()에서 intr_enable()을 호출.

---

## **타이머 값 오버플로우 고려 필요?**
- 64비트 signed 정수로 표현(초당 100틱 기준 약 2조 9천억년까지 안전).
- 오버플로우 걱정 필요 없음.

---

## **우선순위 스케줄링은 starvation(기아 현상) 발생?**
- 엄격한 우선순위 스케줄링은 starvation 가능.
- advanced scheduler에서는 우선순위가 동적으로 변함.
- 실시간 시스템에서는 엄격한 우선순위가 유용(공정성보다 긴급성).

---

## **락 해제 후 어떤 스레드가 실행되어야 하나?**
- 락을 기다리던 스레드 중 **가장 높은 우선순위**의 스레드를 깨워야 함.
- 스케줄러도 ready list에서 가장 높은 우선순위 스레드를 실행.

---

## **최고 우선순위 스레드가 yield하면 계속 실행?**
- 네. 블록되거나 종료되지 않는 한 계속 실행.
- 만약 동일 우선순위 스레드가 여러 개면 round-robin 방식으로 전환됨.

---

## **우선순위 기부 시 donor의 우선순위 변화?**
- 기부는 받은 쪽(donated-to thread) 우선순위만 변화.
- donor(thread A)가 thread B에게 기부하면 B의 우선순위가 A와 같아짐(합산 아님).

---

## **ready queue에 있는 스레드의 우선순위 변경 가능?**
- 예. 예시: 락을 점유한 낮은 우선순위 스레드가 high-priority 스레드에게 기부받을 수 있음.

---

## **blocked 상태에서도 우선순위가 바뀔 수 있나?**
- 네. 락을 점유한 스레드가 blocked된 상태에서 high-priority 스레드가 락을 요청하면 기부받을 수 있음.

---

## **ready list에 추가된 스레드가 프로세서 선점 가능?**
- 네. running thread보다 높은 우선순위면 즉시 선점해야 함(다음 인터럽트까지 기다리면 안 됨).

---

## **thread_set_priority()와 기부된 스레드의 관계?**
- thread_set_priority()는 base priority를 설정.
- effective priority는 base와 기부받은 우선순위 중 더 높은 값.
- 기부가 끝나면 base priority로 복귀.

---

## **테스트 출력에 테스트 이름이 두 번 찍히는 경우?**
- 여러 스레드의 출력이 섞여서 생기는 현상.
- 예: (alarm-priority) (alarm-priority) Thread priority 30 woke up.
- 높은 우선순위 스레드가 실행 중일 때 낮은 스레드가 실행되는 문제(스케줄러 버그).
- PintOS printf()는 콘솔 락을 사용해 출력이 섞이는 걸 방지하지만, 테스트 이름과 메시지가 각각 따로 printf 호출되어 락이 두 번 걸림.

---

## **priority donation과 advanced scheduler의 상호작용?**
- 동시에 테스트하지 않음(별개).

---

## **큐를 64개 대신 1개만 써도 되는가?**
- 동작만 동일하다면 구현 방식은 달라도 됨.

---

## **고급 스케줄러 테스트 실패 시 원인?**
- 테스트 소스/주석을 꼼꼼히 읽고 목적과 기대 결과 확인.
- fixed-point 연산과 스케줄러의 사용법 점검.
- timer 인터럽트에서 너무 많은 작업을 하면, 인터럽트 이후 스레드가 실제로 일할 시간에 불이익 발생.
- 이로 인해 그 스레드의 recent_cpu 값이 부풀려지고, 우선순위가 낮아지며, 스케줄링이 이상해질 수 있음.

---

**요약**  
- 코드양: 대략 300~400줄 내외(참고 솔루션 기준)
- 파일 추가/수정 시 Makefile 관리
- 우선순위, 락, 스케줄러, 인터럽트 동작 등 원리와 디테일 중요
- starvation, priority donation, 선점, 스케줄러 로직 등 꼭 숙지

필요하면 각 항목에 대한 더 구체적인 설명/예시/실제 코드 안내 가능합니다!

lib/kernel 쪽에 데이터 구조 등등있더라

# Alarm Clock 구현
Translation of call stack:
pass tests/threads/alarm-single
pass tests/threads/alarm-multiple
pass tests/threads/alarm-simultaneous
FAIL tests/threads/alarm-priority
pass tests/threads/alarm-zero
pass tests/threads/alarm-negative
FAIL tests/threads/priority-change
FAIL tests/threads/priority-donate-one
FAIL tests/threads/priority-donate-multiple
FAIL tests/threads/priority-donate-multiple2
FAIL tests/threads/priority-donate-nest
FAIL tests/threads/priority-donate-sema
FAIL tests/threads/priority-donate-lower
FAIL tests/threads/priority-fifo
FAIL tests/threads/priority-preempt
FAIL tests/threads/priority-sema
FAIL tests/threads/priority-condvar
FAIL tests/threads/priority-donate-chain
FAIL tests/threads/mlfqs/mlfqs-load-1
FAIL tests/threads/mlfqs/mlfqs-load-60
FAIL tests/threads/mlfqs/mlfqs-load-avg
FAIL tests/threads/mlfqs/mlfqs-recent-1
pass tests/threads/mlfqs/mlfqs-fair-2
pass tests/threads/mlfqs/mlfqs-fair-20
FAIL tests/threads/mlfqs/mlfqs-nice-2
FAIL tests/threads/mlfqs/mlfqs-nice-10
FAIL tests/threads/mlfqs/mlfqs-block
20 of 27 tests failed.
make[1]: *** [../../tests/Make.tests:29: check] Error 1
make[1]: Leaving directory '/workspaces/pintos_22.04_lab_docker/pintos/threads/build'
make: *** [../Makefile.kernel:10: check] Error 2


# priority 기본 추가
Translation of call stack:
pass tests/threads/alarm-single
pass tests/threads/alarm-multiple
pass tests/threads/alarm-simultaneous
pass tests/threads/alarm-priority
pass tests/threads/alarm-zero
pass tests/threads/alarm-negative
pass tests/threads/priority-change
FAIL tests/threads/priority-donate-one
FAIL tests/threads/priority-donate-multiple
FAIL tests/threads/priority-donate-multiple2
FAIL tests/threads/priority-donate-nest
FAIL tests/threads/priority-donate-sema
FAIL tests/threads/priority-donate-lower
pass tests/threads/priority-fifo
pass tests/threads/priority-preempt
FAIL tests/threads/priority-sema
FAIL tests/threads/priority-condvar
FAIL tests/threads/priority-donate-chain
FAIL tests/threads/mlfqs/mlfqs-load-1
FAIL tests/threads/mlfqs/mlfqs-load-60
FAIL tests/threads/mlfqs/mlfqs-load-avg
FAIL tests/threads/mlfqs/mlfqs-recent-1
pass tests/threads/mlfqs/mlfqs-fair-2
pass tests/threads/mlfqs/mlfqs-fair-20
FAIL tests/threads/mlfqs/mlfqs-nice-2
FAIL tests/threads/mlfqs/mlfqs-nice-10
FAIL tests/threads/mlfqs/mlfqs-block
16 of 27 tests failed.
make[1]: *** [../../tests/Make.tests:29: check] Error 1
make[1]: Leaving directory '/workspaces/pintos_22.04_lab_docker/pintos/threads/build'
make: *** [../Makefile.kernel:10: check] Error 2

# priority + sema/condvar fix
pass tests/threads/alarm-single
pass tests/threads/alarm-multiple
pass tests/threads/alarm-simultaneous
pass tests/threads/alarm-priority
pass tests/threads/alarm-zero
pass tests/threads/alarm-negative
pass tests/threads/priority-change
FAIL tests/threads/priority-donate-one
FAIL tests/threads/priority-donate-multiple
FAIL tests/threads/priority-donate-multiple2
FAIL tests/threads/priority-donate-nest
FAIL tests/threads/priority-donate-sema
FAIL tests/threads/priority-donate-lower
pass tests/threads/priority-fifo
pass tests/threads/priority-preempt
pass tests/threads/priority-sema
pass tests/threads/priority-condvar
FAIL tests/threads/priority-donate-chain
FAIL tests/threads/mlfqs/mlfqs-load-1
FAIL tests/threads/mlfqs/mlfqs-load-60
FAIL tests/threads/mlfqs/mlfqs-load-avg
FAIL tests/threads/mlfqs/mlfqs-recent-1
pass tests/threads/mlfqs/mlfqs-fair-2
pass tests/threads/mlfqs/mlfqs-fair-20
FAIL tests/threads/mlfqs/mlfqs-nice-2
FAIL tests/threads/mlfqs/mlfqs-nice-10
FAIL tests/threads/mlfqs/mlfqs-block
14 of 27 tests failed.

# 기본적인 단일 PD 추가
pass tests/threads/alarm-single
pass tests/threads/alarm-multiple
pass tests/threads/alarm-simultaneous
pass tests/threads/alarm-priority
pass tests/threads/alarm-zero
pass tests/threads/alarm-negative
pass tests/threads/priority-change
pass tests/threads/priority-donate-one
FAIL tests/threads/priority-donate-multiple
pass tests/threads/priority-donate-multiple2
FAIL tests/threads/priority-donate-nest
FAIL tests/threads/priority-donate-sema
FAIL tests/threads/priority-donate-lower
FAIL tests/threads/priority-fifo
pass tests/threads/priority-preempt
FAIL tests/threads/priority-sema
FAIL tests/threads/priority-condvar
FAIL tests/threads/priority-donate-chain
FAIL tests/threads/mlfqs/mlfqs-load-1
FAIL tests/threads/mlfqs/mlfqs-load-60
FAIL tests/threads/mlfqs/mlfqs-load-avg
FAIL tests/threads/mlfqs/mlfqs-recent-1
pass tests/threads/mlfqs/mlfqs-fair-2
pass tests/threads/mlfqs/mlfqs-fair-20
FAIL tests/threads/mlfqs/mlfqs-nice-2
FAIL tests/threads/mlfqs/mlfqs-nice-10
FAIL tests/threads/mlfqs/mlfqs-block
15 of 27 tests failed.
make: *** [../../tests/Make.tests:29: check] Error 1
-> 
추가 pass:
priority-donate-one, priority-donate-multiple2
추가 fail:
priority-fifo, 
priority-sema,
priority-condvar 

# 중첩된 PD 추가  처리
Translation of call stack:
pass tests/threads/alarm-single
pass tests/threads/alarm-multiple
pass tests/threads/alarm-simultaneous
pass tests/threads/alarm-priority
pass tests/threads/alarm-zero
pass tests/threads/alarm-negative
FAIL tests/threads/priority-change
pass tests/threads/priority-donate-one
pass tests/threads/priority-donate-multiple
pass tests/threads/priority-donate-multiple2
pass tests/threads/priority-donate-nest
pass tests/threads/priority-donate-sema
FAIL tests/threads/priority-donate-lower
FAIL tests/threads/priority-fifo
pass tests/threads/priority-preempt
FAIL tests/threads/priority-sema
FAIL tests/threads/priority-condvar
FAIL tests/threads/priority-donate-chain
FAIL tests/threads/mlfqs/mlfqs-load-1
FAIL tests/threads/mlfqs/mlfqs-load-60
FAIL tests/threads/mlfqs/mlfqs-load-avg
FAIL tests/threads/mlfqs/mlfqs-recent-1
pass tests/threads/mlfqs/mlfqs-fair-2
pass tests/threads/mlfqs/mlfqs-fair-20
FAIL tests/threads/mlfqs/mlfqs-nice-2
FAIL tests/threads/mlfqs/mlfqs-nice-10
FAIL tests/threads/mlfqs/mlfqs-block
13 of 27 tests failed.
->
priority-donate-multiple,
priority-donate-nest,
priority-donate-sema가 추가로 통과

priority-change가 실패함

# thread_set_priority에선 오리지널을 바꿔야함
pass tests/threads/alarm-single
pass tests/threads/alarm-multiple
pass tests/threads/alarm-simultaneous
pass tests/threads/alarm-priority
pass tests/threads/alarm-zero
pass tests/threads/alarm-negative
pass tests/threads/priority-change
pass tests/threads/priority-donate-one
pass tests/threads/priority-donate-multiple
pass tests/threads/priority-donate-multiple2
pass tests/threads/priority-donate-nest
pass tests/threads/priority-donate-sema
pass tests/threads/priority-donate-lower
pass tests/threads/priority-fifo
pass tests/threads/priority-preempt
pass tests/threads/priority-sema
FAIL tests/threads/priority-condvar
pass tests/threads/priority-donate-chain
FAIL tests/threads/mlfqs/mlfqs-load-1
FAIL tests/threads/mlfqs/mlfqs-load-60
FAIL tests/threads/mlfqs/mlfqs-load-avg
FAIL tests/threads/mlfqs/mlfqs-recent-1
pass tests/threads/mlfqs/mlfqs-fair-2
pass tests/threads/mlfqs/mlfqs-fair-20
FAIL tests/threads/mlfqs/mlfqs-nice-2
FAIL tests/threads/mlfqs/mlfqs-nice-10
FAIL tests/threads/mlfqs/mlfqs-block
8 of 27 tests failed.
->
FAIL tests/threads/priority-condvar
이것만 남음

# 와 이건 진짜 뭔 ?? 퇴물 검색
pass tests/threads/alarm-single
pass tests/threads/alarm-multiple
pass tests/threads/alarm-simultaneous
pass tests/threads/alarm-priority
pass tests/threads/alarm-zero
pass tests/threads/alarm-negative
pass tests/threads/priority-change
pass tests/threads/priority-donate-one
pass tests/threads/priority-donate-multiple
pass tests/threads/priority-donate-multiple2
pass tests/threads/priority-donate-nest
pass tests/threads/priority-donate-sema
pass tests/threads/priority-donate-lower
pass tests/threads/priority-fifo
pass tests/threads/priority-preempt
pass tests/threads/priority-sema
pass tests/threads/priority-condvar
pass tests/threads/priority-donate-chain
FAIL tests/threads/mlfqs/mlfqs-load-1
FAIL tests/threads/mlfqs/mlfqs-load-60
FAIL tests/threads/mlfqs/mlfqs-load-avg
FAIL tests/threads/mlfqs/mlfqs-recent-1
pass tests/threads/mlfqs/mlfqs-fair-2
pass tests/threads/mlfqs/mlfqs-fair-20
FAIL tests/threads/mlfqs/mlfqs-nice-2
FAIL tests/threads/mlfqs/mlfqs-nice-10
FAIL tests/threads/mlfqs/mlfqs-block
7 of 27 tests failed.

make tests/threads/mlfqs/mlfqs-load-1.result

# mlfqs 
pass tests/threads/mlfqs/mlfqs-block
pass tests/threads/alarm-single
pass tests/threads/alarm-multiple
pass tests/threads/alarm-simultaneous
pass tests/threads/alarm-priority
pass tests/threads/alarm-zero
pass tests/threads/alarm-negative
pass tests/threads/priority-change
pass tests/threads/priority-donate-one
pass tests/threads/priority-donate-multiple
pass tests/threads/priority-donate-multiple2
pass tests/threads/priority-donate-nest
pass tests/threads/priority-donate-sema
pass tests/threads/priority-donate-lower
pass tests/threads/priority-fifo
pass tests/threads/priority-preempt
pass tests/threads/priority-sema
pass tests/threads/priority-condvar
pass tests/threads/priority-donate-chain
pass tests/threads/mlfqs/mlfqs-load-1
pass tests/threads/mlfqs/mlfqs-load-60
pass tests/threads/mlfqs/mlfqs-load-avg
pass tests/threads/mlfqs/mlfqs-recent-1
pass tests/threads/mlfqs/mlfqs-fair-2
pass tests/threads/mlfqs/mlfqs-fair-20
pass tests/threads/mlfqs/mlfqs-nice-2
pass tests/threads/mlfqs/mlfqs-nice-10
pass tests/threads/mlfqs/mlfqs-block
All 27 tests passed.