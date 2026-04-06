# AI — AI/ML Security

## Tools
- **py-repl**: numpy, scipy, requests
- WSL: torch, transformers, scikit-learn

## First Steps
1. Identify system: LLM, classifier, image model, custom
2. Interface: API, chat, file upload
3. Baseline: normal input → expected output
4. Goal: prompt injection, adversarial example, model extraction, jailbreak

## Attack Patterns
- **Prompt Injection**: direct ("ignore previous..."), indirect (hidden in content), delimiter confusion, role-play, encoding bypass, multi-turn
- **Adversarial ML**: FGSM/PGD/C&W perturbation, text homoglyphs, model inversion, membership inference
- **Model Extraction**: systematic probing, side channels (timing, confidence), API weight extraction
- **Data Poisoning**: backdoor triggers, label flipping, feature collision

## Pitfalls
- Rate limiting: plan queries carefully
- Token limits: long prompts may truncate
- Non-determinism: retry and average
- Black box: probe before assuming architecture

## Rate-Limit Framework (토큰 절감 핵심)
```
1. 첫 요청 전: X-RateLimit 헤더 확인
2. 접근 한도 파악: N req/min 또는 N req/hour
3. 쿼리 계획 수립 (한도 내에서 최대 정보 추출)
4. Binary search 우선 (O(log N)) > 전수 조사 (O(N))
5. 한도 도달 시: reset 시간까지 대기 (blind retry 금지)
```

## Probe Sequencing (저렴한 것부터)
```
1. Membership inference (토큰 레벨 쿼리) → ~100 tok
2. Confidence/logit extraction → ~500 tok
3. Prompt injection (구조화된 시도) → ~1k tok
4. Full model probing → ~5k+ tok (최후)
```

## Advanced (L4+ only)
- VLM visual injection, typography attacks
- CoT manipulation, system prompt extraction via JSON mode
- Distillation attack, embedding extraction, logprobs exploitation
