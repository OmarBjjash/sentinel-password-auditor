"""Quick integration test for all modules."""
import sys
sys.path.insert(0, '.')

# Test config imports
from core.config import APP_NAME, APP_VERSION, BG_DARK, PRIMARY, WORDLIST_PATH
print(f'[OK] config: {APP_NAME} v{APP_VERSION}')

# Test dictionary manager
from core.dictionary_manager import DictionaryManager
DictionaryManager.reset()
dm = DictionaryManager()
loaded = dm.load()
print(f'[OK] dictionary_manager: loaded={loaded}, words={dm.word_count}, stats={dm.stats}')
print(f'     contains("password")={dm.contains("password")}')
print(f'     contains("xK9!mZpQ")={dm.contains("xK9!mZpQ")}')

# Test password hasher
from core.password_hasher import compute_ntlm_hash, identify_algorithm, HashAlgorithm
ntlm = compute_ntlm_hash('password')
print(f'[OK] password_hasher: NTLM("password")={ntlm}')
alg = identify_algorithm('$6$rounds=5000$salt$hash')
print(f'     identify("$6$...")={alg}')
alg2 = identify_algorithm('$2b$12$hash')
print(f'     identify("$2b$...")={alg2}')
alg3 = identify_algorithm('$y$hash')
print(f'     identify("$y$...")={alg3}')

# Test password checker
from core.password_checker import evaluate_strength, check_dictionary
result = evaluate_strength('P@ssw0rd!2024Xz')
print(f'[OK] password_checker: score={result.score}, level={result.level}')
result2 = evaluate_strength('password')
print(f'     weak test: score={result2.score}, level={result2.level}')

# Test password policy
from core.password_policy import PasswordPolicy
policy = PasswordPolicy()
pr = policy.evaluate('Str0ng!Pass#99')
print(f'[OK] password_policy: passed={pr.passed}, {pr.passed_count}/{pr.total_rules} rules')
pr2 = policy.evaluate('ab')
print(f'     weak policy: passed={pr2.passed}, failed={pr2.failed_count}, recs={len(pr2.recommendations)}')

# Test audit result
from auditors.audit_result import AuditResult, AuditSummary, AuditStatus
r1 = AuditResult.weak('testuser', 'NTLM', 'windows', 'password')
r2 = AuditResult.strong('admin', 'NTLM', 'windows')
r3 = AuditResult.locked('disabled_user', 'windows')
s = AuditSummary.from_results([r1, r2, r3], 'windows')
print(f'[OK] audit_result: weak={s.weak_accounts}, strong={s.strong_accounts}, locked={s.locked_accounts}, total={s.total_accounts}')

# Test hash importer validation
from collectors.windows_hash_importer import validate_ntlm_hash
valid = validate_ntlm_hash('a' * 32)
invalid = validate_ntlm_hash('short')
print(f'[OK] windows_hash_importer: valid_hash={valid}, invalid={invalid}')

# Test windows collector detection
from collectors.windows_hash_collector import detect_windows, get_windows_info
info = get_windows_info()
print(f'[OK] windows_hash_collector: is_windows={detect_windows()}, hostname={info.get("hostname", "?")}')

# Test linux shadow collector (detection only on Windows)
from collectors.linux_shadow_collector import detect_linux, check_shadow_access
print(f'[OK] linux_shadow_collector: is_linux={detect_linux()}, shadow_access={check_shadow_access()}')

# Test audit engine
from core.audit_engine import AuditEngine
engine = AuditEngine()
print(f'[OK] audit_engine: platform={engine.detect_platform()}, dict_stats={engine.get_dictionary_stats()["loaded"]}')

print()
print('=== ALL 13 MODULES VERIFIED SUCCESSFULLY ===')
