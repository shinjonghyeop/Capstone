#!/bin/bash

# 아래 배열에 찾고 싶은 태그들을 추가하세요.
# 예: TARGET_TAGS=("xss" "ssrf" "sqli" "lfi")
TARGET_TAGS=("xss" "ssrf" "cve" "sqli" "rce" "lfi" "rfi" "exposed-panels" "default-logins" "misconfiguration")

# 추가할 태그
TAG_TO_ADD="hacklipse"

echo "Starting script..."
echo "Looking for files with tags: ${TARGET_TAGS[*]}"
echo "Tag to add: $TAG_TO_ADD"
echo "----------------------------------"

# TARGET_TAGS 배열을 기반으로 grep에서 사용할 정규식 패턴을 생성합니다.
# 예: (xss|ssrf)
pattern=$(printf "%s|" "${TARGET_TAGS[@]}")
pattern="(${pattern%|})"

# 현재 디렉토리 및 모든 하위 디렉토리에서 .yaml 파일을 찾습니다.
find . -type f -name "*.yaml" | while IFS= read -r file; do
  # 'tags:' 라인에 TARGET_TAGS 중 하나라도 있고, TAG_TO_ADD가 없는지 확인합니다.
  if grep -qE "tags:.*$pattern" "$file" && ! grep -q "tags:.*$TAG_TO_ADD" "$file"; then
    # sed 대신 perl을 사용하여 파일을 수정합니다. perl은 OS 간 호환성이 더 좋습니다.
    perl -i -pe 's/(tags:.*)/$1,'"$TAG_TO_ADD"'/' "$file"
    echo "Updated tags in: $file"
  fi
done

echo "----------------------------------"
echo "Script finished."
