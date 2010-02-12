#ifndef __ENCODING_H_
#define __ENCODING_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include "encoding.h"

typedef uint8_t str_flag_t;

typedef struct {
    struct RBasic basic;
    encoding_t *encoding;
    long capacity_in_bytes;
    long length_in_bytes;
    union {
	char *bytes;
	UChar *uchars;
    } data;
    str_flag_t flags;
} string_t;

#define STRING_HAS_SUPPLEMENTARY     0x020
#define STRING_HAS_SUPPLEMENTARY_SET 0x010
#define STRING_ASCII_ONLY            0x008
#define STRING_ASCII_ONLY_SET        0x010
#define STRING_ASCII_ONLY            0x008
#define STRING_VALID_ENCODING_SET    0x004
#define STRING_VALID_ENCODING        0x002
#define STRING_STORED_IN_UCHARS      0x001

#define STRING_REQUIRED_FLAGS STRING_STORED_IN_UCHARS

#define STR(x) ((string_t *)(x))

#define BYTES_TO_UCHARS(len) ((len) / sizeof(UChar))
#define UCHARS_TO_BYTES(len) ((len) * sizeof(UChar))

#define ODD_NUMBER(x) ((x) & 0x1)

static long
div_round_up(long a, long b)
{
    return ((a) + (b - 1)) / b;
}

void
str_update_flags(string_t *self);

static void
str_unset_facultative_flags(string_t *self)
{
    self->flags &= ~STRING_HAS_SUPPLEMENTARY_SET & ~STRING_ASCII_ONLY_SET & ~STRING_VALID_ENCODING_SET;
}

static bool
str_known_to_have_an_invalid_encoding(string_t *self)
{
    return (self->flags & (STRING_VALID_ENCODING_SET | STRING_VALID_ENCODING)) == STRING_VALID_ENCODING_SET;
}

static bool
str_known_not_to_have_any_supplementary(string_t *self)
{
    return (self->flags & (STRING_HAS_SUPPLEMENTARY_SET | STRING_HAS_SUPPLEMENTARY)) == STRING_HAS_SUPPLEMENTARY_SET;
}

static bool
str_check_flag_and_update_if_needed(string_t *self, str_flag_t flag_set, str_flag_t flag)
{
    if (!(self->flags & flag_set)) {
	str_update_flags(self);
	assert(self->flags & flag_set);
    }
    return self->flags & flag;
}

static bool
str_is_valid_encoding(string_t *self)
{
    return str_check_flag_and_update_if_needed(self, STRING_VALID_ENCODING_SET, STRING_VALID_ENCODING);
}

static bool
str_is_ascii_only(string_t *self)
{
    return str_check_flag_and_update_if_needed(self, STRING_ASCII_ONLY_SET, STRING_ASCII_ONLY);
}

static bool
str_is_ruby_ascii_only(string_t *self)
{
    // for MRI, a string in a non-ASCII-compatible encoding (like UTF-16)
    // containing only ASCII characters is not "ASCII only" though for us it is internally
    if (!self->encoding->ascii_compatible) {
	return false;
    }

    return str_is_ascii_only(self);
}

static bool
str_is_stored_in_uchars(string_t *self)
{
    return self->flags & STRING_STORED_IN_UCHARS;
}

static void
str_negate_stored_in_uchars(string_t *self)
{
    self->flags ^= STRING_STORED_IN_UCHARS;
}

static void
str_set_stored_in_uchars(string_t *self, bool status)
{
    if (status) {
	self->flags |= STRING_STORED_IN_UCHARS;
    }
    else {
	self->flags &= ~STRING_STORED_IN_UCHARS;
    }
}

static void
str_set_facultative_flag(string_t *self, bool status, str_flag_t flag_set, str_flag_t flag)
{
    if (status) {
	self->flags = self->flags | flag_set | flag;
    }
    else {
	self->flags = (self->flags | flag_set) & ~flag;
    }
}

static void
str_set_has_supplementary(string_t *self, bool status)
{
    str_set_facultative_flag(self, status, STRING_HAS_SUPPLEMENTARY_SET, STRING_HAS_SUPPLEMENTARY);
}

static void
str_set_ascii_only(string_t *self, bool status)
{
    str_set_facultative_flag(self, status, STRING_ASCII_ONLY_SET, STRING_ASCII_ONLY);
}

static void
str_set_valid_encoding(string_t *self, bool status)
{
    str_set_facultative_flag(self, status, STRING_VALID_ENCODING_SET, STRING_VALID_ENCODING);
}

#if defined(__cplusplus)
}
#endif

#endif /* __ENCODING_H_ */
