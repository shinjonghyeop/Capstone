"""
로컬 모델 호출 모듈
"""

from typing import List, Optional, Tuple

from transformers import AutoModelForCausalLM, AutoTokenizer

MAX_CONTEXT_FALLBACK = 4096
SAFETY_TOKENS = 256
COMPACT_MAX_NEW_TOKENS = 512

_MODEL_CACHE: Tuple[Optional[str], Optional[AutoTokenizer], Optional[AutoModelForCausalLM]] = (
    None,
    None,
    None,
)


def _load_model(model_name: str) -> Tuple[AutoTokenizer, AutoModelForCausalLM]:
    global _MODEL_CACHE
    cached_name, cached_tokenizer, cached_model = _MODEL_CACHE
    if cached_name == model_name and cached_tokenizer and cached_model:
        return cached_tokenizer, cached_model

    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        dtype="bfloat16",
        device_map="auto"
    )
    _MODEL_CACHE = (model_name, tokenizer, model)
    return tokenizer, model


def _resolve_max_context(tokenizer: AutoTokenizer, model: AutoModelForCausalLM) -> int:
    model_max = getattr(tokenizer, "model_max_length", None)
    if not model_max or model_max > 100000:
        model_max = getattr(getattr(model, "config", None), "max_position_embeddings", None)
    if not model_max or model_max > 100000:
        model_max = MAX_CONTEXT_FALLBACK
    return int(model_max)


def _token_len(tokenizer: AutoTokenizer, text: str) -> int:
    return len(tokenizer.encode(text))


def _split_by_paragraphs(text: str) -> List[str]:
    parts = [p for p in text.split("\n\n") if p.strip()]
    return parts if parts else [text]


def _split_findings_section(prompt: str) -> Optional[Tuple[str, str, str]]:
    start_key = "# 상세 취약점 입력\n"
    end_key = "\n---\n"
    start_idx = prompt.find(start_key)
    end_idx = prompt.find(end_key)
    if start_idx == -1 or end_idx == -1 or end_idx <= start_idx:
        return None
    prefix = prompt[: start_idx + len(start_key)]
    findings = prompt[start_idx + len(start_key): end_idx]
    suffix = prompt[end_idx:]
    return prefix, findings, suffix


def _generate_text(
    tokenizer: AutoTokenizer,
    model: AutoModelForCausalLM,
    prompt: str,
    max_new_tokens: int,
    temperature: float
) -> str:
    messages = [{"role": "user", "content": prompt}]
    input_ids = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=True,
        return_tensors="pt"
    )

    outputs = model.generate(
        input_ids.to(model.device),
        max_new_tokens=max_new_tokens,
        do_sample=False,
        temperature=temperature
    )
    generated_tokens = outputs[0][input_ids.shape[-1]:]
    return tokenizer.decode(generated_tokens, skip_special_tokens=True)


def _compact_chunk(
    tokenizer: AutoTokenizer,
    model: AutoModelForCausalLM,
    chunk_text: str
) -> str:
    compact_prompt = (
        "다음은 보고서 입력의 일부입니다. 형식을 유지한 채로 간결화하세요.\n"
        "- 항목은 삭제하지 말 것\n"
        "- 문장은 한 줄 불릿으로 축약\n"
        "- 설명/영향/증거는 1줄로 줄일 것\n"
        "- 출력은 이 입력 파트만 반환\n\n"
        f"{chunk_text}"
    )
    return _generate_text(
        tokenizer,
        model,
        compact_prompt,
        max_new_tokens=COMPACT_MAX_NEW_TOKENS,
        temperature=0.0
    )


def _compact_prompt(
    tokenizer: AutoTokenizer,
    model: AutoModelForCausalLM,
    prompt: str,
    max_input_tokens: int
) -> str:
    split = _split_findings_section(prompt)
    if not split:
        parts = _split_by_paragraphs(prompt)
        summaries = []
        for part in parts:
            if _token_len(tokenizer, part) > max_input_tokens:
                summaries.append(_compact_chunk(tokenizer, model, part))
            else:
                summaries.append(part)
        return "\n\n".join(summaries)

    prefix, findings, suffix = split
    findings_parts = _split_by_paragraphs(findings)
    compacted_parts = []
    current = []
    current_tokens = 0

    for part in findings_parts:
        part_tokens = _token_len(tokenizer, part)
        if current and current_tokens + part_tokens > max_input_tokens:
            compacted_parts.append("\n\n".join(current))
            current = []
            current_tokens = 0
        current.append(part)
        current_tokens += part_tokens

    if current:
        compacted_parts.append("\n\n".join(current))

    compacted = []
    for chunk in compacted_parts:
        compacted.append(_compact_chunk(tokenizer, model, chunk))

    compacted_findings = "\n\n".join(compacted)
    return f"{prefix}{compacted_findings}{suffix}"


def generate_with_local_model(
    prompt: str,
    model_name: str,
    temperature: float = 0.7,
    max_new_tokens: int = 1024,
    device: Optional[str] = None
) -> str:
    """
    Transformers 기반 로컬 모델 호출
    """
    tokenizer, model = _load_model(model_name)

    if device:
        model = model.to(device)

    max_context = _resolve_max_context(tokenizer, model)
    max_input_tokens = max(max_context - max_new_tokens - SAFETY_TOKENS, 256)

    prompt_tokens = _token_len(tokenizer, prompt)
    if prompt_tokens > max_input_tokens:
        prompt = _compact_prompt(tokenizer, model, prompt, max_input_tokens)

    return _generate_text(tokenizer, model, prompt, max_new_tokens, temperature)
