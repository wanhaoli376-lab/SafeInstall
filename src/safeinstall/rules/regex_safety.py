"""Conservative structural checks for declarative regular expressions."""

from __future__ import annotations

from dataclasses import dataclass
from re import _parser
from typing import Any


class UnsafeRegexError(ValueError):
    """Raised when a rule pattern falls outside the bounded safe subset."""


_REPEAT_OPERATIONS = {
    _parser.MAX_REPEAT,
    _parser.MIN_REPEAT,
    _parser.POSSESSIVE_REPEAT,
}
_REFERENCE_OPERATIONS = {_parser.GROUPREF, _parser.GROUPREF_EXISTS}
_ASCII = frozenset(range(128))


@dataclass(frozen=True, slots=True)
class _StartSet:
    ascii: frozenset[int]
    may_match_non_ascii: bool = False

    def union(self, other: _StartSet) -> _StartSet:
        return _StartSet(
            self.ascii | other.ascii,
            self.may_match_non_ascii or other.may_match_non_ascii,
        )


def validate_regex_structure(pattern: str) -> None:
    """Reject common structures that can cause super-linear backtracking.

    This is deliberately conservative. Complex expressions should live in a
    purpose-built scanner where their work can be bounded directly.
    """

    parsed = _parser.parse(pattern, 0)
    _validate_sequence(parsed, inside_repeat=False)


def _validate_sequence(sequence: Any, *, inside_repeat: bool) -> None:
    previous_repeat_start: _StartSet | None = None
    for operation, argument in sequence:
        is_repeat = operation in _REPEAT_OPERATIONS
        if operation in _REFERENCE_OPERATIONS:
            raise UnsafeRegexError("backreferences are not allowed in declarative rules")
        if is_repeat:
            _minimum, maximum, repeated = argument
            if inside_repeat:
                raise UnsafeRegexError("nested repetition is not allowed")
            repeated_start, _nullable = _sequence_start(repeated)
            if previous_repeat_start is not None and _may_overlap(
                previous_repeat_start, repeated_start
            ):
                raise UnsafeRegexError("overlapping adjacent repetitions are not allowed")
            _validate_sequence(repeated, inside_repeat=maximum > 1)
        elif operation is _parser.BRANCH:
            if inside_repeat:
                raise UnsafeRegexError("repeated alternatives are not allowed")
            _none, branches = argument
            for branch in branches:
                _validate_sequence(branch, inside_repeat=inside_repeat)
        elif operation is _parser.SUBPATTERN:
            _group, _add_flags, _delete_flags, nested = argument
            _validate_sequence(nested, inside_repeat=inside_repeat)
        elif operation in {_parser.ASSERT, _parser.ASSERT_NOT}:
            _direction, nested = argument
            _validate_sequence(nested, inside_repeat=inside_repeat)
        elif operation is _parser.ATOMIC_GROUP:
            _validate_sequence(argument, inside_repeat=inside_repeat)
        previous_repeat_start = repeated_start if is_repeat else None


def _may_overlap(left: _StartSet, right: _StartSet) -> bool:
    return bool(left.ascii & right.ascii) or (
        left.may_match_non_ascii and right.may_match_non_ascii
    )


def _sequence_start(sequence: Any) -> tuple[_StartSet, bool]:
    result = _StartSet(frozenset())
    for operation, argument in sequence:
        current, nullable = _operation_start(operation, argument)
        result = result.union(current)
        if not nullable:
            return result, False
    return result, True


def _operation_start(operation: Any, argument: Any) -> tuple[_StartSet, bool]:
    if operation is _parser.LITERAL:
        return _literal_start(argument), False
    if operation is _parser.NOT_LITERAL:
        excluded = _literal_start(argument).ascii
        return _StartSet(_ASCII - excluded, True), False
    if operation is _parser.IN:
        return _character_class_start(argument), False
    if operation is _parser.CATEGORY:
        return _category_start(argument), False
    if operation is _parser.ANY:
        return _StartSet(_ASCII, True), False
    if operation is _parser.BRANCH:
        _none, branches = argument
        result = _StartSet(frozenset())
        nullable = False
        for branch in branches:
            branch_start, branch_nullable = _sequence_start(branch)
            result = result.union(branch_start)
            nullable = nullable or branch_nullable
        return result, nullable
    if operation is _parser.SUBPATTERN:
        _group, _add_flags, _delete_flags, nested = argument
        return _sequence_start(nested)
    if operation in _REPEAT_OPERATIONS:
        minimum, _maximum, repeated = argument
        start, nullable = _sequence_start(repeated)
        return start, minimum == 0 or nullable
    if operation is _parser.ATOMIC_GROUP:
        return _sequence_start(argument)
    if operation in {_parser.AT, _parser.ASSERT, _parser.ASSERT_NOT}:
        return _StartSet(frozenset()), True
    return _StartSet(_ASCII, True), False


def _literal_start(codepoint: int) -> _StartSet:
    if codepoint >= 128:
        return _StartSet(frozenset(), True)
    characters = {codepoint}
    character = chr(codepoint)
    if character.isalpha():
        characters.update({ord(character.lower()), ord(character.upper())})
    return _StartSet(frozenset(characters))


def _character_class_start(items: Any) -> _StartSet:
    negated = any(operation is _parser.NEGATE for operation, _argument in items)
    result = _StartSet(frozenset())
    for operation, argument in items:
        if operation is _parser.LITERAL:
            result = result.union(_literal_start(argument))
        elif operation is _parser.RANGE:
            lower, upper = argument
            ascii_values = {value for value in range(max(0, lower), min(127, upper) + 1)}
            for value in tuple(ascii_values):
                ascii_values.update(_literal_start(value).ascii)
            result = result.union(_StartSet(frozenset(ascii_values), upper >= 128))
        elif operation is _parser.CATEGORY:
            result = result.union(_category_start(argument))
    if negated:
        return _StartSet(_ASCII - result.ascii, True)
    return result


def _category_start(category: Any) -> _StartSet:
    digits = frozenset(range(ord("0"), ord("9") + 1))
    spaces = frozenset(ord(character) for character in " \t\n\r\v\f")
    word = (
        digits
        | frozenset(range(ord("a"), ord("z") + 1))
        | frozenset(range(ord("A"), ord("Z") + 1))
        | {ord("_")}
    )
    if category is _parser.CATEGORY_DIGIT:
        return _StartSet(digits, True)
    if category is _parser.CATEGORY_NOT_DIGIT:
        return _StartSet(_ASCII - digits, True)
    if category is _parser.CATEGORY_SPACE:
        return _StartSet(spaces, True)
    if category is _parser.CATEGORY_NOT_SPACE:
        return _StartSet(_ASCII - spaces, True)
    if category is _parser.CATEGORY_WORD:
        return _StartSet(frozenset(word), True)
    if category is _parser.CATEGORY_NOT_WORD:
        return _StartSet(_ASCII - word, True)
    return _StartSet(_ASCII, True)
