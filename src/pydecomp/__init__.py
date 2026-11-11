"""pydecomp — static Python deobfuscator.

Recover readable source from packed, encoded or compiled Python without
ever executing the sample.

The package is layered (engine -> eval -> bytecode -> crypto/decoders).
This module re-exports the whole surface, so `pydecomp.dig(...)` works as
readily as importing a submodule directly.
"""
from __future__ import annotations

from .limits import __version__

from .bytecode.codeobj import CodeObj, _last_module_code, codeobj_from_host
from .bytecode.decompiler6 import (
    D6Null, D6RegionEnd, D6Unsupported, D6_AUG_OPS, D6_BIN_OPS,
    D6_BRIDGE_OPS, D6_CMP_OPS, D6_EPILOGUE_GAP, D6_LAYOUT_OPS, D6_LOADS_ONE,
    D6_LOAD_FAST_OPS, D6_NB_SUBSCR, D6_NULL, D6_SKIP, D6_STORE_FAST_OPS,
    D6_STORE_NAME_OPS, DECOMP_IGNORE, Decompiler6, FASTY, NAMED,
    STRUCTURAL_ONLY, _classdef, _last_engine, _op_histogram, _operand_key,
    _ratio, _streams, _streams_host, content_coverage, cross_version_score,
    d6_trim, fix_stray_returns, roundtrip_score, sanitize_tree,
)
from .bytecode.disassembler import disassemble
from .bytecode.folding import (
    FOLD_BUILTINS, FOLD_METHODS, FOLD_METHOD_MAX, FOLD_MODULES, FoldLimit,
    Folder, _apply_compare, _bind, _mangled_identifier, _pure_module,
    _safe_call, d6_expr_fixups, fold_tree, looks_obfuscated,
)
from .bytecode.harvest import harvest_constants, harvest_inline_text
from .bytecode.lifter import (
    CLASS_BOOKKEEPING, LEFTOVER_MARK, Tok, VALUE_LOADERS, _PydecompUnknown,
    _argnames, _bound_and_loaded, _d6_fix_breaks, _flit, _fmt,
    _fold_ternary, _is_class_body, _not_callable, _resolve_target, _skip_padding,
    audit_line, audit_source, clamp_indent, clean_class_body, compile_problem,
    d6_const, d6_is_back_edge, d6_until_backward_or, fix_empty_blocks, name_audit,
    render, sanitize,
)
from .bytecode.magic import MAGIC_VERSIONS, MAGIC_VERSIONS_BYTES, host_version, parse_pyc
from .bytecode.marshal_reader import (
    FLAG_REF, MarshalReader, _MarshalProxy, iter_code, parse_marshal_blob,
)
from .bytecode.opcodes.tables import (
    BINARY_SYMS, COMPARE_SYMS, OPNAMES, _OPCODE_TEXT, _opname_tables,
)
from .bytecode.roundtrip import (
    _paired_functions, _stream_pairs, exact_match, identity_report,
)
from .bytecode.version_score import _version_score
from .cli import main, selftest
from .core.util import (
    _as_text, _cap, _inflate, _payload_variants, _strip_pkcs7,
    looks_like_python, to_bytes,
)
from .core.values import Val
from .crypto.aes import AES, INV, INV_SBOX, MUL, RCON, SBOX, _mul, _xtime
from .crypto.blowfish import (
    Blowfish, _PI_WORDS, _pi_hex_words, blowfish_cbc_decrypt, blowfish_ecb_decrypt,
    des_ecb_decrypt,
)
from .crypto.chacha20 import _chacha_block, _rotl32, chacha20_xor
from .crypto.des import (
    _DES_E, _DES_FP, _DES_IP, _DES_P, _DES_PC1,
    _DES_PC2, _DES_SBOX, _DES_SHIFTS, _des_block, _des_subkeys,
    _permute, des3_cbc_decrypt, des_cbc_decrypt,
)
from .crypto.fernet import fernet_decrypt
from .crypto.gcm import _gcm_tag, _gf_mult, _ghash, gcm_decrypt, gcm_encrypt
from .crypto.modes import (
    _pad, _unpad, cbc_decrypt, cbc_encrypt, cfb_decrypt,
    ctr_block_xor, ctr_xor, ecb_decrypt, ofb_decrypt,
)
from .crypto.poly1305 import (
    _chacha20poly1305_keys, chacha20poly1305_open, chacha20poly1305_seal, poly1305_mac,
)
from .crypto.rc4 import rc4
from .crypto.shims import (
    CIPHER_CONSTANTS, CIPHER_SCHEMES, FACTORIES, _Aead, _BlockCipher,
    _BlowfishAdapter, _BlowfishCipher, _CipherObject, _CryptoCipher, _CryptoDecryptor,
    _DesCipher, _ExprCipher, _FernetObject, _HashObject, _Instance,
    _StreamCipher, _expr_cipher_new, _factory_aead, _factory_algorithm, _factory_algorithms_aes,
    _factory_cipher_final, _factory_cryptography_cipher, _factory_fernet, _factory_mode, _factory_pycryptodome_new,
    _factory_stream, _make_mode_factory,
)
from .decoders.base16_codec import _hex_strict
from .decoders.base45_codec import B45_ALPHABET, b45decode
from .decoders.base58_codec import B58_ALPHABET, b58decode
from .decoders.base62_codec import _base62
from .decoders.base91_codec import (
    B91_ALPHABET, _B91_ALLOWED, _B91_TABLE, _b91_plausible, b91decode,
)
from .decoders.compression.zlib_codec import _zlib_stream
from .decoders.emoji import (
    _EMOJI_BLOCKS, _EMOJI_POOLS, _EMOJI_SETS, _chacha_layer, _emoji_base_chain,
    _emoji_byte_chain, _emoji_density, _emoji_transforms, _looks_emoji, parses_as_python,
)
from .decoders.escapes import _escaped_bytes
from .decoders.hex_loose import _hex_loose, _strip_separators
from .decoders.registry import (
    TRANSFORMS, _BINARY_CODECS, _PRINT_TABLE, _TEXT_ONLY, _mostly_text,
    _printable_count, _transform_allowed,
)
from .decoders.rot13 import _rot13_strict
from .decoders.xor import _XOR_WEIGHT, _key_score, _score_text, _xor_with, xor_best
from .decoders.z85 import _base85_z85
from .engine.artifact import Artifact, _score
from .engine.decode import (
    _DECODE_CACHE, _DECODE_CACHE_CAP, _DEEP, _deep_decode_uncached, _deep_mode,
    deep_decode,
)
from .engine.dig import (
    _digest_bytes, _follow_expression_payload, _follow_source, _from_code, carve_strings,
    dig,
)
from .engine.normalize import UNKNOWN_PREAMBLE, normalize, with_unknown_preamble
from .engine.peel import Layer, Payload, find_payloads, peel
from .engine.run import _strip_pydecomp_preamble, deobfuscate, deobfuscate_tree
from .eval.builtins import _REFUSED_BUILTINS, _safe_builtin, _safe_compile
from .eval.evaluator import Evaluator
from .eval.expr_eval import (
    EXPR_BUILTINS, EXPR_MODULES, ExprEval, _EXPR_STEP_BUDGET, _LocalReturn,
    _coerce_payload, resolve_expression_payload,
)
from .eval.namespace import (
    _AlgorithmHandle, _BuiltinsModule, _CryptoModule, _DecryptorFactory, _FakeSys,
    _ImportlibModule, _ModeHandle, _NameSpace,
)
from .eval.sentinel import _EXEC_SENTINELS, _ExecSentinel
from .eval.whitelist import (
    BUILTINS, METHOD_NAMES_EXTRA, MODULE_NAMES, WHITELIST, _builtin_bytes,
    _builtin_chr, _builtin_compile, _builtin_int, _builtin_map, _builtin_ord,
    _from_bytes, _int_to_bytes, _mk_whitelist,
)
from .exceptions import (
    EvalFailed, EvalUnsafe, MarshalPayload, _BreakSignal, _ContinueSignal,
    _EXC_BY_NAME, _ExprCaptured, _ExprRefuse, _ReturnSignal, const_int,
)
from .lift.classes import _CLASS_BODY_KEYS, promote_class_bodies
from .lift.module import (
    LIFT_QUALITY, SIZE_BUDGET, _append_missing_units, _last_module_version, _lift_module5,
    _lift_module6, decompile_accepted, decompile_code6, decompile_object, lift,
    lift_module,
)
from .lift.quality import ensure_parseable
from .limits import EXEC_SINKS, MAX_DECOMPRESSED, MAX_LAYERS, MAX_SOURCE, __version__
from .output.paths import phone_dir, unique_path
from .output.save import save
from .polish.apply import polish_source
from .polish.dead import _strip_dead
from .polish.demangle import _ast, _demangle, _mangled_name
from .polish.fold import (
    _MAX_FOLD_LENGTH, _const_node, _eval_const, _fold_constants, _fold_literals,
    _pure_constant,
)
from .polish.neutralize import _GUARD_MARKERS, _is_guard, neutralize_source
from .polish.unflatten import _unflatten
from .terminal.animate import SPIN, animate_bar, animate_text, clear, rule, spinner, width
from .terminal.banner import LOGO, LOGO_TINT, banner, header
from .terminal.color import (
    ANSI_RE, BLUE, INTERACTIVE, USE_COLOR, ask,
    die, ellipsis, ok, paint, step,
    vlen, warn,
)
from .terminal.menu import ask_file, interactive_loop, menu
from .terminal.panel import panel
from .triage.behavior import _RISKY
from .triage.fingerprint import _fingerprint
from .triage.iocs import _IOC_PATTERNS
from .triage.pyarmor import (
    _PYARMOR_MARKERS, extract_pyarmor_blobs, pyarmor_markers, pyarmor_note,
)
from .triage.report import analyse_recovered, render_report, write_reports
from .triage.verify import _exec_dry_run

__all__ = ["__version__"] + [
    "CodeObj",
    "_last_module_code",
    "codeobj_from_host",
    "D6Null",
    "D6RegionEnd",
    "D6Unsupported",
    "D6_AUG_OPS",
    "D6_BIN_OPS",
    "D6_BRIDGE_OPS",
    "D6_CMP_OPS",
    "D6_EPILOGUE_GAP",
    "D6_LAYOUT_OPS",
    "D6_LOADS_ONE",
    "D6_LOAD_FAST_OPS",
    "D6_NB_SUBSCR",
    "D6_NULL",
    "D6_SKIP",
    "D6_STORE_FAST_OPS",
    "D6_STORE_NAME_OPS",
    "DECOMP_IGNORE",
    "Decompiler6",
    "FASTY",
    "NAMED",
    "STRUCTURAL_ONLY",
    "_classdef",
    "_last_engine",
    "_op_histogram",
    "_operand_key",
    "_ratio",
    "_streams",
    "_streams_host",
    "content_coverage",
    "cross_version_score",
    "d6_trim",
    "fix_stray_returns",
    "roundtrip_score",
    "sanitize_tree",
    "disassemble",
    "FOLD_BUILTINS",
    "FOLD_METHODS",
    "FOLD_METHOD_MAX",
    "FOLD_MODULES",
    "FoldLimit",
    "Folder",
    "_apply_compare",
    "_bind",
    "_mangled_identifier",
    "_pure_module",
    "_safe_call",
    "d6_expr_fixups",
    "fold_tree",
    "looks_obfuscated",
    "harvest_constants",
    "harvest_inline_text",
    "CLASS_BOOKKEEPING",
    "LEFTOVER_MARK",
    "Tok",
    "VALUE_LOADERS",
    "_PydecompUnknown",
    "_argnames",
    "_bound_and_loaded",
    "_d6_fix_breaks",
    "_flit",
    "_fmt",
    "_fold_ternary",
    "_is_class_body",
    "_not_callable",
    "_resolve_target",
    "_skip_padding",
    "audit_line",
    "audit_source",
    "clamp_indent",
    "clean_class_body",
    "compile_problem",
    "d6_const",
    "d6_is_back_edge",
    "d6_until_backward_or",
    "fix_empty_blocks",
    "name_audit",
    "render",
    "sanitize",
    "MAGIC_VERSIONS",
    "MAGIC_VERSIONS_BYTES",
    "host_version",
    "parse_pyc",
    "FLAG_REF",
    "MarshalReader",
    "_MarshalProxy",
    "iter_code",
    "parse_marshal_blob",
    "BINARY_SYMS",
    "COMPARE_SYMS",
    "OPNAMES",
    "_OPCODE_TEXT",
    "_opname_tables",
    "_paired_functions",
    "_stream_pairs",
    "exact_match",
    "identity_report",
    "_version_score",
    "main",
    "selftest",
    "_as_text",
    "_cap",
    "_inflate",
    "_payload_variants",
    "_strip_pkcs7",
    "looks_like_python",
    "to_bytes",
    "Val",
    "AES",
    "INV",
    "INV_SBOX",
    "MUL",
    "RCON",
    "SBOX",
    "_mul",
    "_xtime",
    "Blowfish",
    "_PI_WORDS",
    "_pi_hex_words",
    "blowfish_cbc_decrypt",
    "blowfish_ecb_decrypt",
    "des_ecb_decrypt",
    "_chacha_block",
    "_rotl32",
    "chacha20_xor",
    "_DES_E",
    "_DES_FP",
    "_DES_IP",
    "_DES_P",
    "_DES_PC1",
    "_DES_PC2",
    "_DES_SBOX",
    "_DES_SHIFTS",
    "_des_block",
    "_des_subkeys",
    "_permute",
    "des3_cbc_decrypt",
    "des_cbc_decrypt",
    "fernet_decrypt",
    "_gcm_tag",
    "_gf_mult",
    "_ghash",
    "gcm_decrypt",
    "gcm_encrypt",
    "_pad",
    "_unpad",
    "cbc_decrypt",
    "cbc_encrypt",
    "cfb_decrypt",
    "ctr_block_xor",
    "ctr_xor",
    "ecb_decrypt",
    "ofb_decrypt",
    "_chacha20poly1305_keys",
    "chacha20poly1305_open",
    "chacha20poly1305_seal",
    "poly1305_mac",
    "rc4",
    "CIPHER_CONSTANTS",
    "CIPHER_SCHEMES",
    "FACTORIES",
    "_Aead",
    "_BlockCipher",
    "_BlowfishAdapter",
    "_BlowfishCipher",
    "_CipherObject",
    "_CryptoCipher",
    "_CryptoDecryptor",
    "_DesCipher",
    "_ExprCipher",
    "_FernetObject",
    "_HashObject",
    "_Instance",
    "_StreamCipher",
    "_expr_cipher_new",
    "_factory_aead",
    "_factory_algorithm",
    "_factory_algorithms_aes",
    "_factory_cipher_final",
    "_factory_cryptography_cipher",
    "_factory_fernet",
    "_factory_mode",
    "_factory_pycryptodome_new",
    "_factory_stream",
    "_make_mode_factory",
    "_hex_strict",
    "B45_ALPHABET",
    "b45decode",
    "B58_ALPHABET",
    "b58decode",
    "_base62",
    "B91_ALPHABET",
    "_B91_ALLOWED",
    "_B91_TABLE",
    "_b91_plausible",
    "b91decode",
    "_zlib_stream",
    "_EMOJI_BLOCKS",
    "_EMOJI_POOLS",
    "_EMOJI_SETS",
    "_chacha_layer",
    "_emoji_base_chain",
    "_emoji_byte_chain",
    "_emoji_density",
    "_emoji_transforms",
    "_looks_emoji",
    "parses_as_python",
    "_escaped_bytes",
    "_hex_loose",
    "_strip_separators",
    "TRANSFORMS",
    "_BINARY_CODECS",
    "_PRINT_TABLE",
    "_TEXT_ONLY",
    "_mostly_text",
    "_printable_count",
    "_transform_allowed",
    "_rot13_strict",
    "_XOR_WEIGHT",
    "_key_score",
    "_score_text",
    "_xor_with",
    "xor_best",
    "_base85_z85",
    "Artifact",
    "_score",
    "_DECODE_CACHE",
    "_DECODE_CACHE_CAP",
    "_DEEP",
    "_deep_decode_uncached",
    "_deep_mode",
    "deep_decode",
    "_digest_bytes",
    "_follow_expression_payload",
    "_follow_source",
    "_from_code",
    "carve_strings",
    "dig",
    "UNKNOWN_PREAMBLE",
    "normalize",
    "with_unknown_preamble",
    "Layer",
    "Payload",
    "find_payloads",
    "peel",
    "_strip_pydecomp_preamble",
    "deobfuscate",
    "deobfuscate_tree",
    "_REFUSED_BUILTINS",
    "_safe_builtin",
    "_safe_compile",
    "Evaluator",
    "EXPR_BUILTINS",
    "EXPR_MODULES",
    "ExprEval",
    "_EXPR_STEP_BUDGET",
    "_LocalReturn",
    "_coerce_payload",
    "resolve_expression_payload",
    "_AlgorithmHandle",
    "_BuiltinsModule",
    "_CryptoModule",
    "_DecryptorFactory",
    "_FakeSys",
    "_ImportlibModule",
    "_ModeHandle",
    "_NameSpace",
    "_EXEC_SENTINELS",
    "_ExecSentinel",
    "BUILTINS",
    "METHOD_NAMES_EXTRA",
    "MODULE_NAMES",
    "WHITELIST",
    "_builtin_bytes",
    "_builtin_chr",
    "_builtin_compile",
    "_builtin_int",
    "_builtin_map",
    "_builtin_ord",
    "_from_bytes",
    "_int_to_bytes",
    "_mk_whitelist",
    "EvalFailed",
    "EvalUnsafe",
    "MarshalPayload",
    "_BreakSignal",
    "_ContinueSignal",
    "_EXC_BY_NAME",
    "_ExprCaptured",
    "_ExprRefuse",
    "_ReturnSignal",
    "const_int",
    "_CLASS_BODY_KEYS",
    "promote_class_bodies",
    "LIFT_QUALITY",
    "SIZE_BUDGET",
    "_append_missing_units",
    "_last_module_version",
    "_lift_module5",
    "_lift_module6",
    "decompile_accepted",
    "decompile_code6",
    "decompile_object",
    "lift",
    "lift_module",
    "ensure_parseable",
    "EXEC_SINKS",
    "MAX_DECOMPRESSED",
    "MAX_LAYERS",
    "MAX_SOURCE",
    "__version__",
    "phone_dir",
    "unique_path",
    "save",
    "polish_source",
    "_strip_dead",
    "_ast",
    "_demangle",
    "_mangled_name",
    "_MAX_FOLD_LENGTH",
    "_const_node",
    "_eval_const",
    "_fold_constants",
    "_fold_literals",
    "_pure_constant",
    "_GUARD_MARKERS",
    "_is_guard",
    "neutralize_source",
    "_unflatten",
    "SPIN",
    "animate_bar",
    "animate_text",
    "clear",
    "rule",
    "spinner",
    "width",
    "LOGO",
    "LOGO_TINT",
    "banner",
    "header",
    "ANSI_RE",
    "BLUE",
    "INTERACTIVE",
    "USE_COLOR",
    "ask",
    "die",
    "ellipsis",
    "ok",
    "paint",
    "step",
    "vlen",
    "warn",
    "ask_file",
    "interactive_loop",
    "menu",
    "panel",
    "_RISKY",
    "_fingerprint",
    "_IOC_PATTERNS",
    "_PYARMOR_MARKERS",
    "extract_pyarmor_blobs",
    "pyarmor_markers",
    "pyarmor_note",
    "analyse_recovered",
    "render_report",
    "write_reports",
    "_exec_dry_run",
]
