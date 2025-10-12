#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------
# Wapiti 자동 설치 (git + 의존성 자동 처리, venv 감지)
# - git clone / pull
# - pyproject.toml에서 의존성 추출 후 설치
# - 부족 모듈(ModuleNotFoundError) 자동 보완 설치 (최대 5회)
# - venv 안이면 --user 금지, venv 밖이면 기본 --user 설치
# - 옵션으로 시스템 전역 설치 지원 (--system)
# -----------------------------------------

REPO_URL="https://github.com/wapiti-scanner/wapiti.git"
BRANCH="master"
SRC_DIR="${HOME}/.src/wapiti"
SYSTEM_WIDE="0"   # 0: --user(로컬) / 1: 시스템 전역

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)     REPO_URL="${2:-}"; shift 2 ;;
    --branch)   BRANCH="${2:-}";   shift 2 ;;
    --src-dir)  SRC_DIR="${2:-}";  shift 2 ;;
    --system)   SYSTEM_WIDE="1";   shift 1 ;;
    -h|--help)
      echo "사용법: $0 [--repo <url>] [--branch <name>] [--src-dir <path>] [--system]"
      exit 0 ;;
    *) echo "알 수 없는 옵션: $1" >&2; exit 1 ;;
  esac
done

echo "[*] REPO : $REPO_URL"
echo "[*] BRANCH: $BRANCH"
echo "[*] SRC   : $SRC_DIR"
echo "[*] MODE  : $([[ "$SYSTEM_WIDE" = "1" ]] && echo SYSTEM || echo USER)"

# ---------- venv 감지 ----------
IN_VENV=0
if [ -n "${VIRTUAL_ENV:-}" ]; then
  IN_VENV=1
else
  python3 - <<'PY' >/dev/null 2>&1 || true
import sys
# venv면 sys.prefix != sys.base_prefix
raise SystemExit(0 if (hasattr(sys,'base_prefix') and sys.prefix!=sys.base_prefix) else 1)
PY
  [ $? -eq 0 ] && IN_VENV=1
fi
echo "[*] IN_VENV: $IN_VENV (1이면 가상환경)"

# ---------- sudo/패키지 매니저 ----------
need_sudo() { [[ "$(id -u)" -ne 0 ]]; }
SUDO=""
if need_sudo; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else
    echo "[!] sudo 없음. root로 실행하거나 sudo를 설치하세요." >&2; exit 1
  fi
fi

PM=""; PM_TYPE=""
if command -v apt >/dev/null 2>&1; then PM="apt"; PM_TYPE="debian"
elif command -v dnf >/dev/null 2>&1; then PM="dnf"; PM_TYPE="fedora"
elif command -v yum >/dev/null 2>&1; then PM="yum"; PM_TYPE="rhel"
elif command -v pacman >/dev/null 2>&1; then PM="pacman"; PM_TYPE="arch"
elif command -v zypper >/dev/null 2>&1; then PM="zypper"; PM_TYPE="suse"
else
  echo "[!] 지원 패키지 매니저를 찾지 못했습니다. python3/pip/git을 수동 설치하세요." >&2; exit 1
fi

install_basics() {
  echo "[*] 패키지 매니저: $PM ($PM_TYPE) - python3/pip/git 및 빌드 툴 설치"
  case "$PM_TYPE" in
    debian)
      $SUDO apt update -y
      $SUDO apt install -y python3 python3-pip git build-essential python3-dev \
        libxml2-dev libxslt1-dev libffi-dev libssl-dev
      ;;
    fedora)
      $SUDO dnf install -y python3 python3-pip git gcc python3-devel \
        libxml2-devel libxslt-devel libffi-devel openssl-devel
      ;;
    rhel)
      $SUDO yum install -y python3 python3-pip git gcc python3-devel \
        libxml2-devel libxslt-devel libffi-devel openssl-devel
      ;;
    arch)
      $SUDO pacman -Sy --noconfirm python python-pip git base-devel libxml2 libxslt libffi openssl
      ;;
    suse)
      $SUDO zypper refresh
      $SUDO zypper install -y python3 python3-pip git gcc python3-devel \
        libxml2-devel libxslt-devel libffi-devel libopenssl-devel
      ;;
  esac
}

ensure_cmd() {
  local c="$1"
  if ! command -v "$c" >/dev/null 2>&1; then
    echo "[!] '$c' 미설치 → 설치 진행"
    install_basics
  else
    echo "[OK] $c: $("$c" --version 2>/dev/null || echo installed)"
  fi
}
ensure_cmd python3
ensure_cmd pip3
ensure_cmd git

# ---------- pip 설치 래퍼 (venv/시스템/로컬 자동 결정) ----------
pip_install() {
  if [[ "$SYSTEM_WIDE" = "1" ]]; then
    # (주의) 일부 배포판은 --break-system-packages 필요
    $SUDO python3 -m pip install "$@" || $SUDO python3 -m pip install --break-system-packages "$@"
  else
    if [[ "$IN_VENV" -eq 1 ]]; then
      python3 -m pip install "$@"
    else
      python3 -m pip install --user "$@"
    fi
  fi
}

# ---------- 소스 준비 (clone/pull) ----------
mkdir -p "$(dirname "$SRC_DIR")"
if [[ -d "$SRC_DIR/.git" ]]; then
  echo "[*] 기존 레포 → 최신화"
  git -C "$SRC_DIR" remote set-url origin "$REPO_URL" || true
  git -C "$SRC_DIR" fetch origin
  git -C "$SRC_DIR" checkout "$BRANCH"
  git -C "$SRC_DIR" pull --ff-only origin "$BRANCH"
else
  echo "[*] git clone: $REPO_URL → $SRC_DIR (branch: $BRANCH)"
  git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$SRC_DIR"
fi

cd "$SRC_DIR"

# ---------- pip 최신화 ----------
pip_install --upgrade pip setuptools wheel

# ---------- pyproject.toml 의존성 추출 및 설치 ----------
REQ_FILE="${SRC_DIR}/requirements.txt"
: > "$REQ_FILE"
if [[ -f "pyproject.toml" ]]; then
  echo "[*] pyproject.toml → 의존성 추출"
  PY_CMD='
import sys
try:
    import tomllib
except Exception:
    try:
        import tomli as tomllib
    except Exception:
        sys.exit(0)

with open("pyproject.toml","rb") as f:
    data = tomllib.load(f)

deps=[]
proj=data.get("project") or {}
deps += proj.get("dependencies") or []
tool=data.get("tool") or {}
poetry=tool.get("poetry") or {}
deps += poetry.get("dependencies") or []

out=[]
for d in deps:
    if isinstance(d,str):
        if d.lower().strip()=="python":
            continue
        out.append(d.split(";")[0].split("#")[0].strip())
for d in out:
    if d:
        print(d)
'
  PARSED="$(python3 -c "$PY_CMD" || true)"
  if [[ -n "$PARSED" ]]; then
    echo "$PARSED" > "$REQ_FILE"
    echo "[*] 추출된 의존성:"
    cat "$REQ_FILE" || true
    pip_install -r "$REQ_FILE"
  else
    echo "[*] 의존성 항목 없음/파서 사용 불가 → 다음 단계"
  fi
else
  echo "[*] pyproject.toml 없음 → 다음 단계"
fi

# ---------- Wapiti 본체 설치 ----------
echo "[*] 패키지 설치: pip install ."
pip_install .
pip_install "passlib>=1.7.4" "bcrypt<4" #bcrypt 버전을 낮춰야지 설치완료됨

# ---------- 부족 모듈 자동 보완 루프 ----------
MAX_RETRY=5
MISS_REQ="${SRC_DIR}/requirements.missing.txt"
: > "$MISS_REQ"
echo "[*] 부족 모듈 자동 보완 (최대 ${MAX_RETRY}회)"
for ((i=1;i<=MAX_RETRY;i++)); do
  set +e
  OUT="$(wapiti --version 2>&1)"
  CODE=$?
  set -e
  if [[ $CODE -eq 0 ]]; then
    echo "$OUT"
    echo "[*] 실행 성공"
    break
  fi
  MISSING="$(echo "$OUT" | grep -Eo "ModuleNotFoundError: No module named '([^']+)'" | sed "s/.*'//;s/'//")" || true
  if [[ -n "$MISSING" ]]; then
    echo "[!] 누락 모듈: $MISSING"
    if ! grep -qx "$MISSING" "$MISS_REQ"; then echo "$MISSING" >> "$MISS_REQ"; fi
    pip_install -r "$MISS_REQ"
  else
    echo "[!] 알 수 없는 오류:"
    echo "$OUT"
    break
  fi
done

# ---------- PATH 안내 (로컬 설치 시)
if [[ "$SYSTEM_WIDE" = "0" && "$IN_VENV" -eq 0 ]]; then
  if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
    echo
    echo "[i] ~/.local/bin 이 PATH에 없다면 다음을 실행하세요:"
    echo '    echo "export PATH=$HOME/.local/bin:$PATH" >> ~/.bashrc && source ~/.bashrc'
  fi
fi

echo
echo "[✓] 완료: 'wapiti --version'으로 최종 확인하세요."
[[ -s "$REQ_FILE" ]] && echo "[i] 추출된 의존성 파일: $REQ_FILE"
[[ -s "$MISS_REQ" ]] && echo "[i] 보완된 의존성 파일: $MISS_REQ"
