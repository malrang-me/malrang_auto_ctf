# 이것도 딸깍해 보시지! (ddalgak)

- **Platform**: Dreamhack
- **Category**: Misc
- **Level**: 1
- **Flag**: `DH{AI_Stands_For_Artificial_Idiot_haha}`
- **Date**: 2026-03-29

## Challenge Summary

PDF(`homework.pdf`)에 Python 코드가 있고, 실행 결과를 `nc` 서버에 제출하면 플래그를 받는 문제.

## Core Trick: PDF Text Extraction Trap

이 문제는 **AI/복붙으로 풀면 틀리도록 설계된 함정 문제**다.

### 함정 1: 연산자 변경
PDF에서 텍스트를 추출(복사)하면 연산자가 바뀐다:
- 실제 PDF 이미지: `x > 110` (strict) -> 텍스트 추출: `x>=110`
- 실제 PDF 이미지: `x < 70` (strict) -> 텍스트 추출: `x<=70`

### 함정 2: 들여쓰기(indentation) 파괴
PDF 이미지에서는 **두 개의 독립적인 if 블록**이 for 루프 안에 있다:

```python
for x in item:
    # Block 1
    if x > 110:
        answer += 'A'
    elif x < 70:
        answer += 'B'
    elif x <= 90:
        answer += 'C'
    # Block 2 (separate if, NOT elif!)
    if x % 3 == 1:
        answer += 'A'
    elif x % 4 < 3:
        answer += 'B'
    else:
        answer += 'C'
```

하지만 텍스트 추출 시 두 번째 `if`가 `elif`로 읽혀 하나의 if-elif 체인으로 잘못 해석됨.

### 결과
- 매 반복마다 Block 1에서 0~1개, Block 2에서 1개 = 최대 2개 문자 추가
- 90 < x <= 110인 경우 Block 1은 skip, Block 2만 실행

## Solution

```python
item = [115,65,97,88,55,110,100,90,67,75,80,84,70,110,120,92,103]
answer = ""
for x in item:
    if x > 110:
        answer += 'A'
    elif x < 70:
        answer += 'B'
    elif x <= 90:
        answer += 'C'
    if x % 3 == 1:
        answer += 'A'
    elif x % 4 < 3:
        answer += 'B'
    else:
        answer += 'C'
print(answer)  # AABBACABABACBBACCCBCBCABABBA
```

Answer: `AABBACABABACBBACCCBCBCABABBA`

## Key Takeaway

PDF 문제는 반드시 **이미지로 렌더링해서** 코드를 확인해야 한다. 텍스트 추출(pdftotext, pymupdf get_text 등)은 연산자, 들여쓰기, 특수문자를 변경할 수 있다.
