/* 
 * MacRuby implementation of Ruby 1.9's string.c.
 *
 * This file is covered by the Ruby license. See COPYING for more details.
 * 
 * Copyright (C) 2007-2009, Apple Inc. All rights reserved.
 * Copyright (C) 1993-2007 Yukihiro Matsumoto
 * Copyright (C) 2000 Network Applied Communication Laboratory, Inc.
 * Copyright (C) 2000 Information-technology Promotion Agency, Japan
 */
#include "unicode/ustring.h"
#include "unicode/ucnv.h"
#include "ruby.h"
#include "objc.h"
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define OBJC_CLASS(x) (*(VALUE *)(x))

// TODO:
// - use rb_usascii_str_new_cstr instead of rb_str_new2

VALUE rb_cMREncoding;

typedef struct {
    struct RBasic basic;
    unsigned int index;
    const char *public_name;
    const char **aliases;
    unsigned int aliases_count;
    unsigned char min_char_size;
    bool single_byte_encoding : 1;
    bool ascii_compatible : 1;
    UConverter *converter;
} encoding_t;

#define ENC(x) ((encoding_t *)(x))

encoding_t *default_internal = NULL;
encoding_t *default_external = NULL;

enum {
    ENCODING_BINARY = 0,
    ENCODING_ASCII,
    ENCODING_UTF8,
    ENCODING_UTF16BE,
    ENCODING_UTF16LE,
    ENCODING_UTF32BE,
    ENCODING_UTF32LE,
    ENCODING_ISO8859_1,
    //ENCODING_EUCJP,
    //ENCODING_SJIS,
    //ENCODING_CP932,

    ENCODINGS_COUNT
};

#if __LITTLE_ENDIAN__
#define ENCODING_UTF16_NATIVE ENCODING_UTF16LE
#define ENCODING_UTF32_NATIVE ENCODING_UTF32LE
#define ENCODING_UTF16_NON_NATIVE ENCODING_UTF16BE
#define ENCODING_UTF32_NON_NATIVE ENCODING_UTF32BE
#else
#define ENCODING_UTF16_NATIVE ENCODING_UTF16BE
#define ENCODING_UTF32_NATIVE ENCODING_UTF32BE
#define ENCODING_UTF16_NON_NATIVE ENCODING_UTF16LE
#define ENCODING_UTF32_NON_NATIVE ENCODING_UTF32LE
#endif

static encoding_t *encodings[ENCODINGS_COUNT];

#define NATIVE_UTF16_ENC(enc) ((enc) == encodings[ENCODING_UTF16_NATIVE])
#define NON_NATIVE_UTF16_ENC(enc) ((enc) == encodings[ENCODING_UTF16_NON_NATIVE])
#define UTF16_ENC(enc) (NATIVE_UTF16_ENC(enc) || NON_NATIVE_UTF16_ENC(enc))
#define NATIVE_UTF32_ENC(enc) ((enc) == encodings[ENCODING_UTF32_NATIVE])
#define NON_NATIVE_UTF32_ENC(enc) ((enc) == encodings[ENCODING_UTF32_NON_NATIVE])
#define UTF32_ENC(enc) (NATIVE_UTF32_ENC(enc) || NON_NATIVE_UTF32_ENC(enc))
#define BINARY_ENC(enc) ((enc) == encodings[ENCODING_BINARY])

static VALUE
mr_enc_s_list(VALUE klass, SEL sel)
{
    VALUE ary = rb_ary_new2(ENCODINGS_COUNT);
    for (unsigned int i = 0; i < ENCODINGS_COUNT; ++i) {
	rb_ary_push(ary, (VALUE)encodings[i]);
    }
    return ary;
}

static VALUE
mr_enc_s_name_list(VALUE klass, SEL sel)
{
    VALUE ary = rb_ary_new();
    for (unsigned int i = 0; i < ENCODINGS_COUNT; ++i) {
	encoding_t *enc = ENC(encodings[i]);
	// TODO: use US-ASCII strings
	rb_ary_push(ary, rb_str_new2(enc->public_name));
	for (unsigned int j = 0; j < enc->aliases_count; ++j) {
	    rb_ary_push(ary, rb_str_new2(enc->aliases[j]));
	}
    }
    return ary;
}

static VALUE
mr_enc_s_aliases(VALUE klass, SEL sel)
{
    VALUE hash = rb_hash_new();
    for (unsigned int i = 0; i < ENCODINGS_COUNT; ++i) {
	encoding_t *enc = ENC(encodings[i]);
	for (unsigned int j = 0; j < enc->aliases_count; ++j) {
	    rb_hash_aset(hash,
		    rb_str_new2(enc->aliases[j]),
		    rb_str_new2(enc->public_name));
	}
    }
    return hash;
}

static VALUE
mr_enc_s_default_internal(VALUE klass, SEL sel)
{
    return (VALUE)default_internal;
}

static VALUE
mr_enc_s_default_external(VALUE klass, SEL sel)
{
    return (VALUE)default_external;
}

static VALUE
mr_enc_name(VALUE self, SEL sel)
{
    return rb_str_new2(ENC(self)->public_name);
}

static VALUE
mr_enc_inspect(VALUE self, SEL sel)
{
    return rb_sprintf("#<%s:%s>", rb_obj_classname(self), ENC(self)->public_name);
}

static VALUE
mr_enc_names(VALUE self, SEL sel)
{
    encoding_t *encoding = ENC(self);

    VALUE ary = rb_ary_new2(encoding->aliases_count + 1);
    rb_ary_push(ary, rb_str_new2(encoding->public_name));
    for (unsigned int i = 0; i < encoding->aliases_count; ++i) {
	rb_ary_push(ary, rb_str_new2(encoding->aliases[i]));
    }
    return ary;
}

static VALUE
mr_enc_ascii_compatible_p(VALUE self, SEL sel)
{
    return ENC(self)->ascii_compatible ? Qtrue : Qfalse;
}

static VALUE
mr_enc_dummy_p(VALUE self, SEL sel)
{
    return Qfalse;
}

static void
define_encoding_constant(const char *name, encoding_t *enc)
{
    char c = name[0];
    if ((c >= '0') && (c <= '9')) {
	// constants can't start with a number
	return;
    }

    char *name_copy = strdup(name);
    if ((c >= 'a') && (c <= 'z')) {
	// the first character must be upper case
	name_copy[0] = c - ('a' - 'A');
    }

    // '.' and '-' must be transformed into '_'
    for (int i = 0; name_copy[i]; ++i) {
	if ((name_copy[i] == '.') || (name_copy[i] == '-')) {
	    name_copy[i] = '_';
	}
    }
    rb_define_const(rb_cMREncoding, name_copy, (VALUE)enc);
    free(name_copy);
}

static void
add_encoding(
	unsigned int encoding_index, // index of the encoding in the encodings array
	const char *public_name, // public name for the encoding
	unsigned char min_char_size,
	bool single_byte_encoding, // in the encoding a character takes only one byte
	bool ascii_compatible, // is the encoding ASCII compatible or not
	... // aliases for the encoding (should no include the public name) - must end with a NULL
	)
{
    assert(encoding_index < ENCODINGS_COUNT);

    // create an array for the aliases
    unsigned int aliases_count = 0;
    va_list va_aliases;
    va_start(va_aliases, ascii_compatible);
    while (va_arg(va_aliases, const char *) != NULL) {
	++aliases_count;
    }
    va_end(va_aliases);
    const char **aliases = (const char **) malloc(sizeof(const char *) * aliases_count);
    va_start(va_aliases, ascii_compatible);
    for (unsigned int i = 0; i < aliases_count; ++i) {
	aliases[i] = va_arg(va_aliases, const char *);
    }
    va_end(va_aliases);

    // create the ICU converter
    UConverter *converter;
    if (encoding_index == ENCODING_BINARY) {
	converter = NULL; // no converter for binary
    }
    else {
	UErrorCode err = U_ZERO_ERROR;
	converter = ucnv_open(public_name, &err);
	if (!U_SUCCESS(err) || (converter == NULL)) {
	    fprintf(stderr, "Couldn't create the encoder for %s\n", public_name);
	    abort();
	}
	// stop the conversion when the conversion failed
	err = U_ZERO_ERROR;
	ucnv_setToUCallBack(converter, UCNV_TO_U_CALLBACK_STOP, NULL, NULL, NULL, &err);
	err = U_ZERO_ERROR;
	ucnv_setFromUCallBack(converter, UCNV_FROM_U_CALLBACK_STOP, NULL, NULL, NULL, &err);
    }

    // create the MacRuby object
    NEWOBJ(enc, encoding_t);
    enc->basic.flags = 0;
    enc->basic.klass = rb_cMREncoding;
    encodings[encoding_index] = enc;
    rb_objc_retain(enc); // it should never be deallocated

    // fill the fields
    enc->index = encoding_index;
    enc->public_name = public_name;
    enc->min_char_size = min_char_size;
    enc->single_byte_encoding = single_byte_encoding;
    enc->ascii_compatible = ascii_compatible;
    enc->aliases_count = aliases_count;
    enc->aliases = aliases;
    enc->converter = converter;

    // create constants
    define_encoding_constant(public_name, enc);
    for (unsigned int i = 0; i < aliases_count; ++i) {
	define_encoding_constant(aliases[i], enc);
    }
}

static void
create_encodings(void)
{
    add_encoding(ENCODING_BINARY,    "ASCII-8BIT",  1, true,  true,  "BINARY", NULL);
    add_encoding(ENCODING_ASCII,     "US-ASCII",    1, true,  true,  "ASCII", "ANSI_X3.4-1968", "646", NULL);
    add_encoding(ENCODING_UTF8,      "UTF-8",       1, false, true,  "CP65001", NULL);
    add_encoding(ENCODING_UTF16BE,   "UTF-16BE",    2, false, false, NULL);
    add_encoding(ENCODING_UTF16LE,   "UTF-16LE",    2, false, false, NULL);
    add_encoding(ENCODING_UTF32BE,   "UTF-32BE",    4, false, false, "UCS-4BE", NULL);
    add_encoding(ENCODING_UTF32LE,   "UTF-32LE",    4, false, false, "UCS-4LE", NULL);
    add_encoding(ENCODING_ISO8859_1, "ISO-8859-1",  1, true,  true,  "ISO8859-1", NULL);
    // FIXME: the ICU conversion tables do not seem to match Ruby's Japanese conversion tables
    //add_encoding(ENCODING_EUCJP,     "EUC-JP",      1, false, true,  "eucJP", NULL);
    //add_encoding(ENCODING_SJIS,      "Shift_JIS",   1, false, true, "SJIS", NULL);
    //add_encoding(ENCODING_CP932,     "Windows-31J", 1, false, true, "CP932", "csWindows31J", NULL);

    default_external = encodings[ENCODING_UTF8];
    default_internal = encodings[ENCODING_UTF16_NATIVE];
}

static VALUE
mr_enc_s_is_compatible(VALUE klass, SEL sel, VALUE str1, VALUE str2);

void
Init_MREncoding(void)
{
    rb_cMREncoding = rb_define_class("MREncoding", rb_cObject);
    rb_undef_alloc_func(rb_cMREncoding);

    rb_objc_define_method(rb_cMREncoding, "to_s", mr_enc_name, 0);
    rb_objc_define_method(rb_cMREncoding, "inspect", mr_enc_inspect, 0);
    rb_objc_define_method(rb_cMREncoding, "name", mr_enc_name, 0);
    rb_objc_define_method(rb_cMREncoding, "names", mr_enc_names, 0);
    rb_objc_define_method(rb_cMREncoding, "dummy?", mr_enc_dummy_p, 0);
    rb_objc_define_method(rb_cMREncoding, "ascii_compatible?", mr_enc_ascii_compatible_p, 0);
    rb_objc_define_method(OBJC_CLASS(rb_cMREncoding), "list", mr_enc_s_list, 0);
    rb_objc_define_method(OBJC_CLASS(rb_cMREncoding), "name_list", mr_enc_s_name_list, 0);
    rb_objc_define_method(OBJC_CLASS(rb_cMREncoding), "aliases", mr_enc_s_aliases, 0);
    //rb_define_singleton_method(rb_cMREncoding, "find", enc_find, 1);
    // it's defined on Encoding, but it requires String's internals so it's defined with String
    rb_objc_define_method(OBJC_CLASS(rb_cMREncoding), "compatible?", mr_enc_s_is_compatible, 2);

    //rb_define_method(rb_cEncoding, "_dump", enc_dump, -1);
    //rb_define_singleton_method(rb_cEncoding, "_load", enc_load, 1);

    rb_objc_define_method(OBJC_CLASS(rb_cMREncoding), "default_external", mr_enc_s_default_external, 0);
    //rb_define_singleton_method(rb_cMREncoding, "default_external=", set_default_external, 1);
    rb_objc_define_method(OBJC_CLASS(rb_cMREncoding), "default_internal", mr_enc_s_default_internal, 0);
    //rb_define_singleton_method(rb_cMREncoding, "default_internal=", set_default_internal, 1);
    //rb_define_singleton_method(rb_cMREncoding, "locale_charmap", rb_locale_charmap, 0);

    create_encodings();
}

//--------------------- strings ----------------------------

VALUE rb_cMRString;

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

// do not forget to close the converter
// before leaving the function
#define USE_CONVERTER(cnv, str) \
    assert(str->encoding->converter != NULL); \
    char cnv##_buffer[U_CNV_SAFECLONE_BUFFERSIZE]; \
    UErrorCode cnv##_err = U_ZERO_ERROR; \
    int32_t cnv##_buffer_size = U_CNV_SAFECLONE_BUFFERSIZE; \
    UConverter *cnv = ucnv_safeClone( \
	    str->encoding->converter, \
	    cnv##_buffer, \
	    &cnv##_buffer_size, \
	    &cnv##_err \
	); \
    ucnv_reset(cnv);

static void
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

static void
str_update_flags_utf16(string_t *self)
{
    assert(str_is_stored_in_uchars(self) || NON_NATIVE_UTF16_ENC(self->encoding));

    bool ascii_only = true;
    bool has_supplementary = false;
    bool valid_encoding = true;
    // if the length is an odd number, it can't be valid UTF-16
    if (ODD_NUMBER(self->length_in_bytes)) {
	valid_encoding = false;
    }

    UChar *uchars = self->data.uchars;
    long uchars_count = BYTES_TO_UCHARS(self->length_in_bytes);
    bool native_byte_order = str_is_stored_in_uchars(self);
    UChar32 lead = 0;
    for (int i = 0; i < uchars_count; ++i) {
	UChar32 c;
	if (native_byte_order) {
	    c = uchars[i];
	}
	else {
	    uint8_t *bytes = (uint8_t *)&uchars[i];
	    c = (uint16_t)bytes[0] << 8 | (uint16_t)bytes[1];
	}
	if (U16_IS_SURROGATE(c)) { // surrogate
	    if (U16_IS_SURROGATE_LEAD(c)) { // lead surrogate
		// a lead surrogate should not be
		// after an other lead surrogate
		if (lead != 0) {
		    valid_encoding = false;
		}
		lead = c;
	    }
	    else { // trail surrogate
		// a trail surrogate must follow a lead surrogate
		if (lead == 0) {
		    valid_encoding = false;
		}
		else {
		    has_supplementary = true;
		    c = U16_GET_SUPPLEMENTARY(lead, c);
		    if (!U_IS_UNICODE_CHAR(c)) {
			valid_encoding = false;
		    }
		}
		lead = 0;
	    }
	}
	else { // not a surrogate
	    // a non-surrogate character should not be after a lead surrogate
	    // and it should be a valid Unicode character
	    // Warning: Ruby 1.9 does not do the IS_UNICODE_CHAR check
	    // (for 1.9, 0xffff is valid though it's not a Unicode character)
	    if ((lead != 0) || !U_IS_UNICODE_CHAR(c)) {
		valid_encoding = false;
	    }

	    if (c > 127) {
		ascii_only = false;
	    }
	}
    }
    // the last character should not be a lead surrogate
    if (lead != 0) {
	valid_encoding = false;
    }

    str_set_has_supplementary(self, has_supplementary);
    if (valid_encoding) {
	str_set_valid_encoding(self, true);
	str_set_ascii_only(self, ascii_only);
    }
    else {
	str_set_valid_encoding(self, false);
	str_set_ascii_only(self, false);
    }
}

static void
str_update_flags(string_t *self)
{
    if (self->length_in_bytes == 0) {
	str_set_valid_encoding(self, true);
	str_set_ascii_only(self, true);
	str_set_has_supplementary(self, false);
    }
    else if (BINARY_ENC(self->encoding)) {
	str_set_valid_encoding(self, true);
	str_set_has_supplementary(self, false);
	bool ascii_only = true;
	for (long i = 0; i < self->length_in_bytes; ++i) {
	    if ((uint8_t)self->data.bytes[i] > 127) {
		ascii_only = false;
		break;
	    }
	}
	str_set_ascii_only(self, ascii_only);
    }
    else if (str_is_stored_in_uchars(self) || UTF16_ENC(self->encoding)) {
	str_update_flags_utf16(self);
    }
    else {
	USE_CONVERTER(cnv, self);

	bool ascii_only = true;
	bool valid_encoding = true;
	bool has_supplementary = false;

	const char *pos = self->data.bytes;
	const char *end = pos + self->length_in_bytes;
	for (;;) {
	    // iterate through the string one Unicode code point at a time
	    UErrorCode err = U_ZERO_ERROR;
	    UChar32 c = ucnv_getNextUChar(cnv, &pos, end, &err);
	    if (U_FAILURE(err)) {
		if (err == U_INDEX_OUTOFBOUNDS_ERROR) {
		    // end of the string
		    break;
		}
		else {
		    // conversion error
		    valid_encoding = false;
		    ascii_only = false;
		}
	    }
	    else {
		if (c > 127) {
		    ascii_only = false;
		    if (U_IS_SUPPLEMENTARY(c)) {
			has_supplementary = true;
		    }
		}
	    }
	}

	ucnv_close(cnv);

	str_set_has_supplementary(self, has_supplementary);
	str_set_valid_encoding(self, valid_encoding);
	str_set_ascii_only(self, ascii_only);
    }
}

static void
str_invert_byte_order(string_t *self)
{
    assert(NON_NATIVE_UTF16_ENC(self->encoding));

    long length_in_bytes = self->length_in_bytes;
    char *bytes = self->data.bytes;

    if (ODD_NUMBER(length_in_bytes)) {
	--length_in_bytes;
    }

    for (long i = 0; i < length_in_bytes; i += 2) {
	char tmp = bytes[i];
	bytes[i] = bytes[i+1];
	bytes[i+1] = tmp;
    }
    str_negate_stored_in_uchars(self);
}


static encoding_t *
str_compatible_encoding(string_t *str1, string_t *str2)
{
    if (str1->encoding == str2->encoding) {
	return str1->encoding;
    }
    if (str2->length_in_bytes == 0) {
	return str1->encoding;
    }
    if (str1->length_in_bytes == 0) {
	return str2->encoding;
    }
    if (!str1->encoding->ascii_compatible || !str2->encoding->ascii_compatible) {
	return NULL;
    }
    if (str_is_ruby_ascii_only(str1) && str_is_ruby_ascii_only(str2)) {
	return str1->encoding;
    }
    return NULL;
}

static encoding_t *
str_must_have_compatible_encoding(string_t *str1, string_t *str2)
{
    encoding_t *new_encoding = str_compatible_encoding(str1, str2);
    if (new_encoding == NULL) {
	rb_raise(rb_eEncCompatError, "incompatible character encodings: %s and %s",
		str1->encoding->public_name, str2->encoding->public_name);
    }
    return new_encoding;
}


static string_t *
str_alloc(void)
{
    NEWOBJ(str, string_t);
    str->basic.flags = 0;
    str->basic.klass = rb_cMRString;
    str->encoding = encodings[ENCODING_BINARY];
    str->capacity_in_bytes = 0;
    str->length_in_bytes = 0;
    str->data.bytes = NULL;
    str->flags = 0;
    return str;
}

static VALUE
mr_str_s_alloc(VALUE klass)
{
    return (VALUE)str_alloc();
}


extern VALUE rb_cString;
extern VALUE rb_cCFString;
extern VALUE rb_cNSString;
extern VALUE rb_cNSMutableString;
extern VALUE rb_cSymbol;
extern VALUE rb_cByteString;

static void
str_replace(string_t *self, VALUE arg)
{
    VALUE klass = OBJC_CLASS(arg);
    if (klass == rb_cByteString) {
	self->encoding = encodings[ENCODING_BINARY];
	self->capacity_in_bytes = self->length_in_bytes = rb_bytestring_length(arg);
	if (self->length_in_bytes != 0) {
	    GC_WB(&self->data.bytes, xmalloc(self->length_in_bytes));
	    assert(self->data.bytes != NULL);
	    memcpy(self->data.bytes, rb_bytestring_byte_pointer(arg), self->length_in_bytes);
	}
    }
    else if ((klass == rb_cString)
		|| (klass == rb_cCFString)
		|| (klass == rb_cNSString)
		|| (klass == rb_cNSMutableString)) {
	self->encoding = encodings[ENCODING_UTF16_NATIVE];
	self->capacity_in_bytes = self->length_in_bytes = UCHARS_TO_BYTES(CFStringGetLength((CFStringRef)arg));
	if (self->length_in_bytes != 0) {
	    GC_WB(&self->data.uchars, xmalloc(self->length_in_bytes));
	    CFStringGetCharacters((CFStringRef)arg, CFRangeMake(0, BYTES_TO_UCHARS(self->length_in_bytes)), self->data.uchars);
	    str_set_stored_in_uchars(self, true);
	}
    }
    else if (klass == rb_cMRString) {
	string_t *str = STR(arg);
	self->encoding = str->encoding;
	self->capacity_in_bytes = self->length_in_bytes = str->length_in_bytes;
	self->flags = str->flags;
	if (self->length_in_bytes != 0) {
	    GC_WB(&self->data.bytes, xmalloc(self->length_in_bytes));
	    memcpy(self->data.bytes, str->data.bytes, self->length_in_bytes);
	}
    }
    else if (klass == rb_cSymbol) {
	abort(); // TODO
    }
    else {
	abort(); // TODO
    }
}

static void
str_clear(string_t *self)
{
    self->length_in_bytes = 0;
}


static void
str_make_data_binary(string_t *self)
{
    if (!str_is_stored_in_uchars(self) || NATIVE_UTF16_ENC(self->encoding)) {
	// nothing to do
	return;
    }

    if (NON_NATIVE_UTF16_ENC(self->encoding)) {
	// Doing the conversion ourself is faster, and anyway ICU's converter
	// does not like non-paired surrogates.
	str_invert_byte_order(self);
	return;
    }

    USE_CONVERTER(cnv, self);

    UErrorCode err = U_ZERO_ERROR;
    long capa = UCNV_GET_MAX_BYTES_FOR_STRING(BYTES_TO_UCHARS(self->length_in_bytes), ucnv_getMaxCharSize(cnv));
    char *buffer = xmalloc(capa);
    const UChar *source_pos = self->data.uchars;
    const UChar *source_end = self->data.uchars + BYTES_TO_UCHARS(self->length_in_bytes);
    char *target_pos = buffer;
    char *target_end = buffer + capa;
    ucnv_fromUnicode(cnv, &target_pos, target_end, &source_pos, source_end, NULL, true, &err);
    // there should never be any conversion error here
    // (if there's one it means some checking has been forgotten before)
    assert(U_SUCCESS(err));

    ucnv_close(cnv);

    str_set_stored_in_uchars(self, false);
    self->capacity_in_bytes = capa;
    self->length_in_bytes = target_pos - buffer;
    GC_WB(&self->data.bytes, buffer);
}

static long
utf16_bytesize_approximation(encoding_t *enc, int bytesize)
{
    long approximation;
    if (UTF16_ENC(enc)) {
	approximation = bytesize; // the bytesize in UTF-16 is the same whatever the endianness
    }
    else if (UTF32_ENC(enc)) {
	// the bytesize in UTF-16 is nearly half of the bytesize in UTF-32
	// (if there characters not in the BMP it's a bit more though)
	approximation = bytesize / 2;
    }
    else {
	// take a quite large size to not have to reallocate
	approximation = bytesize * 2;
    }

    if (ODD_NUMBER(approximation)) {
	// the size must be an even number
	++approximation;
    }

    return approximation;
}

static bool
str_try_making_data_uchars(string_t *self)
{
    if (str_is_stored_in_uchars(self)) {
	return true;
    }
    else if (NON_NATIVE_UTF16_ENC(self->encoding)) {
	str_invert_byte_order(self);
	return true;
    }
    else if (BINARY_ENC(self->encoding)) {
	// you can't convert binary to anything
	return false;
    }
    else if (self->length_in_bytes == 0) {
	// for empty strings, nothing to convert
	str_set_stored_in_uchars(self, true);
	return true;
    }
    else if (str_known_to_have_an_invalid_encoding(self)) {
	return false;
    }

    USE_CONVERTER(cnv, self);

    long capa = utf16_bytesize_approximation(self->encoding, self->length_in_bytes);
    const char *source_pos = self->data.bytes;
    const char *source_end = self->data.bytes + self->length_in_bytes;
    UChar *buffer = xmalloc(capa);
    UChar *target_pos = buffer;
    UErrorCode err = U_ZERO_ERROR;
    for (;;) {
	UChar *target_end = buffer + BYTES_TO_UCHARS(capa);
	err = U_ZERO_ERROR;
	ucnv_toUnicode(cnv, &target_pos, target_end, &source_pos, source_end, NULL, true, &err);
	if (err == U_BUFFER_OVERFLOW_ERROR) {
	    long index = target_pos - buffer;
	    capa *= 2; // double the buffer's size
	    buffer = xrealloc(buffer, capa);
	    target_pos = buffer + index;
	}
	else {
	    break;
	}
    }

    ucnv_close(cnv);

    if (U_SUCCESS(err)) {
	str_set_valid_encoding(self, true);
	str_set_stored_in_uchars(self, true);
	self->capacity_in_bytes = capa;
	self->length_in_bytes = UCHARS_TO_BYTES(target_pos - buffer);
	GC_WB(&self->data.uchars, buffer);

	return true;
    }
    else {
	str_set_valid_encoding(self, false);

	return false;
    }
}

static long
str_length(string_t *self, bool ucs2_mode)
{
    if (self->length_in_bytes == 0) {
	return 0;
    }
    if (str_is_stored_in_uchars(self)) {
	long length;
	if (ucs2_mode) {
	    length = BYTES_TO_UCHARS(self->length_in_bytes);
	}
	else {
	    // we must return the length in Unicode code points,
	    // not the number of UChars, even if the probability
	    // we have surrogates is very low
	    length = u_countChar32(self->data.uchars, BYTES_TO_UCHARS(self->length_in_bytes));
	}
	if (ODD_NUMBER(self->length_in_bytes)) {
	    return length + 1;
	}
	else {
	    return length;
	}
    }
    else {
	if (self->encoding->single_byte_encoding) {
	    return self->length_in_bytes;
	}
	else if (ucs2_mode && UTF16_ENC(self->encoding)) {
	    long length = BYTES_TO_UCHARS(self->length_in_bytes);
	    if (ODD_NUMBER(self->length_in_bytes)) {
		return length + 1;
	    }
	    else {
		return length;
	    }
	}
	else {
	    USE_CONVERTER(cnv, self);

	    const char *pos = self->data.bytes;
	    const char *end = pos + self->length_in_bytes;
	    long len = 0;
	    bool valid_encoding = true;
	    for (;;) {
		const char *character_start_pos = pos;
		// iterate through the string one Unicode code point at a time
		UErrorCode err = U_ZERO_ERROR;
		UChar32 c = ucnv_getNextUChar(cnv, &pos, end, &err);
		if (err == U_INDEX_OUTOFBOUNDS_ERROR) {
		    // end of the string
		    break;
		}
		else if (U_FAILURE(err)) {
		    valid_encoding = false;
		    long min_char_size = self->encoding->min_char_size;
		    long converted_width = pos - character_start_pos;
		    len += div_round_up(converted_width, min_char_size);
		}
		else {
		    if (ucs2_mode && !U_IS_BMP(c)) {
			len += 2;
		    }
		    else {
			++len;
		    }
		}
	    }

	    ucnv_close(cnv);

	    str_set_valid_encoding(self, valid_encoding);

	    return len;
	}
    }
}

#define STACK_BUFFER_SIZE 1024
static long
str_bytesize(string_t *self)
{
    if (str_is_stored_in_uchars(self)) {
	if (UTF16_ENC(self->encoding)) {
	    return self->length_in_bytes;
	}
	else {
	    // for strings stored in UTF-16 for which the Ruby encoding is not UTF-16,
	    // we have to convert back the string in its original encoding to get the length in bytes
	    USE_CONVERTER(cnv, self);

	    UErrorCode err = U_ZERO_ERROR;

	    long len = 0;
	    char buffer[STACK_BUFFER_SIZE];
	    const UChar *source_pos = self->data.uchars;
	    const UChar *source_end = self->data.uchars + BYTES_TO_UCHARS(self->length_in_bytes);
	    char *target_end = buffer + STACK_BUFFER_SIZE;
	    for (;;) {
		err = U_ZERO_ERROR;
		char *target_pos = buffer;
		ucnv_fromUnicode(cnv, &target_pos, target_end, &source_pos, source_end, NULL, true, &err);
		len += target_pos - buffer;
		if (err != U_BUFFER_OVERFLOW_ERROR) {
		    // if the convertion failed, a check was missing somewhere
		    assert(U_SUCCESS(err));
		    break;
		}
	    }

	    ucnv_close(cnv);
	    return len;
	}
    }
    else {
	return self->length_in_bytes;
    }
}

static bool
str_getbyte(string_t *self, long index, unsigned char *c)
{
    if (str_is_stored_in_uchars(self) && NATIVE_UTF16_ENC(self->encoding)) {
	if (index < 0) {
	    index += self->length_in_bytes;
	    if (index < 0) {
		return false;
	    }
	}
	if (index >= self->length_in_bytes) {
	    return false;
	}
	if (NATIVE_UTF16_ENC(self->encoding)) {
	    *c = self->data.bytes[index];
	}
	else { // non native byte-order UTF-16
	    if ((index & 1) == 0) { // even
		*c = self->data.bytes[index+1];
	    }
	    else { // odd
		*c = self->data.bytes[index-1];
	    }
	}
    }
    else {
	// work with a binary string
	// (UTF-16 strings could be converted to their binary form
	//  on the fly but that would just add complexity)
	str_make_data_binary(self);

	if (index < 0) {
	    index += self->length_in_bytes;
	    if (index < 0) {
		return false;
	    }
	}
	if (index >= self->length_in_bytes) {
	    return false;
	}
	*c = self->data.bytes[index];
    }
    return true;
}

static void
str_setbyte(string_t *self, long index, unsigned char value)
{
    str_make_data_binary(self);
    if ((index < -self->length_in_bytes) || (index >= self->length_in_bytes)) {
	rb_raise(rb_eIndexError, "index %ld out of string", index);
    }
    if (index < 0) {
	index += self->length_in_bytes;
    }
    self->data.bytes[index] = value;
}

static void
str_force_encoding(string_t *self, encoding_t *enc)
{
    if (enc == self->encoding) {
	return;
    }
    str_make_data_binary(self);
    if (NATIVE_UTF16_ENC(self->encoding)) {
	str_set_stored_in_uchars(self, false);
    }
    self->encoding = enc;
    str_unset_facultative_flags(self);
    if (NATIVE_UTF16_ENC(self->encoding)) {
	str_set_stored_in_uchars(self, true);
    }
}

static string_t *
str_new_similar_empty_string(string_t *self)
{
    string_t *str = str_alloc();
    str->encoding = self->encoding;
    str->flags = self->flags & STRING_REQUIRED_FLAGS;
    return str;
}

static string_t *
str_new_copy_of_part(string_t *self, long offset_in_bytes, long length_in_bytes)
{
    string_t *str = str_alloc();
    str->encoding = self->encoding;
    str->capacity_in_bytes = str->length_in_bytes = length_in_bytes;
    str->flags = self->flags & STRING_REQUIRED_FLAGS;
    GC_WB(&str->data.bytes, xmalloc(length_in_bytes));
    memcpy(str->data.bytes, &self->data.bytes[offset_in_bytes], length_in_bytes);
    return str;
}

NORETURN(static void
str_cannot_cut_surrogate(void))
{
    rb_raise(rb_eIndexError, "You can't cut a surrogate in two in an encoding that is not UTF-16");
}

static string_t *
str_get_character_fixed_width(string_t *self, long index, long character_width)
{
    long len = div_round_up(self->length_in_bytes, character_width);
    if (index < 0) {
	index += len;
	if (index < 0) {
	    return NULL;
	}
    }
    else if (index >= len) {
	return NULL;
    }

    // if the string is truncated we can have less data than the character's width
    long offset_in_bytes = index * character_width;
    if (offset_in_bytes + character_width > self->length_in_bytes) {
	character_width = self->length_in_bytes - offset_in_bytes;
    }
    return str_new_copy_of_part(self, offset_in_bytes, character_width);
}

static string_t *
str_get_characters(string_t *self, long start, long end, bool ucs2_mode)
{
    if (self->length_in_bytes == 0) {
	if (start == 0) {
	    return str_new_similar_empty_string(self);
	}
	else {
	    return NULL;
	}
    }
    if (!self->encoding->single_byte_encoding && !str_is_stored_in_uchars(self)) {
	str_try_making_data_uchars(self);
    }
    if (str_is_stored_in_uchars(self)) {
	if (ucs2_mode || str_known_not_to_have_any_supplementary(self)) {
	    long length = BYTES_TO_UCHARS(self->length_in_bytes);
	    if (start < 0) {
		start += length;
		if (start < 0) {
		    return NULL;
		}
	    }
	    if (start > length) {
		return NULL;
	    }
	    if (end < 0) {
		end += length;
	    }
	    if (end <= start) {
		return str_new_similar_empty_string(self);
	    }
	    return str_new_copy_of_part(self, UCHARS_TO_BYTES(start), UCHARS_TO_BYTES(end - start));
	}
	else {
	    abort(); // TODO
	}
    }
    abort(); // TODO
}

// TODO: as get_characters and get_character_at are nearly the same,
// make them one function (with a boolean indicating if it's only for 1 character)
static string_t *
str_get_character_at(string_t *self, long index, bool ucs2_mode)
{
    if (self->length_in_bytes == 0) {
	return NULL;
    }
    if (!self->encoding->single_byte_encoding && !str_is_stored_in_uchars(self)) {
	str_try_making_data_uchars(self);
    }
    if (str_is_stored_in_uchars(self)) {
	if (ucs2_mode || str_known_not_to_have_any_supplementary(self)) {
	    string_t *str = str_get_character_fixed_width(self, index, 2);
	    if ((str != NULL) && U16_IS_SURROGATE(str->data.uchars[0])) {
		if (!UTF16_ENC(str->encoding)) {
		    // you can't cut a surrogate in an encoding that is not UTF-16
		    // (it's in theory possible to store the surrogate in
		    //  UTF-8 or UTF-32 but that would be incorrect Unicode)
		    str_cannot_cut_surrogate();
		}
	    }
	    return str;
	}
	else {
	    // we don't have the length of the string, just the number of UChars
	    // (uchars_count >= number of characters)
	    long uchars_count = BYTES_TO_UCHARS(self->length_in_bytes);
	    if ((index < -uchars_count) || (index >= uchars_count)) {
		return NULL;
	    }
	    const UChar *uchars = self->data.uchars;
	    long offset;
	    if (index < 0) {
		// count the characters from the end
		offset = uchars_count;
		while ((offset > 0) && (index < 0)) {
		    --offset;
		    // if the next character is a paired surrogate
		    // we need to go to the start of the whole surrogate
		    if (U16_IS_TRAIL(uchars[offset]) && (offset > 0) && U16_IS_LEAD(uchars[offset-1])) {
			--offset;
		    }
		    ++index;
		}
		// ended before the index got to 0
		if (index != 0) {
		    return NULL;
		}
		assert(offset >= 0);
	    }
	    else {
		// count the characters from the start
		offset = 0;
		U16_FWD_N(uchars, offset, uchars_count, index);
		if (offset >= uchars_count) {
		    return NULL;
		}
	    }

	    long length_in_bytes;
	    if (U16_IS_LEAD(uchars[offset]) && (offset < uchars_count - 1) && (U16_IS_TRAIL(uchars[offset+1]))) {
		// if it's a lead surrogate we must also copy the trail surrogate
		length_in_bytes = UCHARS_TO_BYTES(2);
	    }
	    else {
		length_in_bytes = UCHARS_TO_BYTES(1);
	    }
	    long offset_in_bytes = UCHARS_TO_BYTES(offset);
	    return str_new_copy_of_part(self, offset_in_bytes, length_in_bytes);
	}
    }
    else { // data in binary
	if (self->encoding->single_byte_encoding) {
	    return str_get_character_fixed_width(self, index, 1);
	}
	else if (!ucs2_mode && UTF32_ENC(self->encoding)) { // UTF-32 only in non UCS-2 mode
	    return str_get_character_fixed_width(self, index, 4);
	}
	else if (NON_NATIVE_UTF16_ENC(self->encoding) && (ucs2_mode || str_known_not_to_have_any_supplementary(self))) {
	    return str_get_character_fixed_width(self, index, 2);
	}
	else {
	    if (index < 0) {
		// calculating the length is slow but we don't have much choice
		index += str_length(self, ucs2_mode);
		if (index < 0) {
		    return NULL;
		}
	    }

	    // the code has many similarities with str_length
	    USE_CONVERTER(cnv, self);

	    const char *pos = self->data.bytes;
	    const char *end = pos + self->length_in_bytes;
	    long current_index = 0;
	    for (;;) {
		const char *character_start_pos = pos;
		// iterate through the string one Unicode code point at a time
		// (we dont care what the character is or if it's valid or not)
		UErrorCode err = U_ZERO_ERROR;
		UChar32 c = ucnv_getNextUChar(cnv, &pos, end, &err);
		if (err == U_INDEX_OUTOFBOUNDS_ERROR) {
		    // end of the string
		    ucnv_close(cnv);
		    return NULL;
		}
		long offset_in_bytes = character_start_pos - self->data.bytes;
		long converted_width = pos - character_start_pos;
		if (U_FAILURE(err)) {
		    long min_char_size = self->encoding->min_char_size;
		    // division of converted_width by min_char_size rounded up
		    long diff = div_round_up(converted_width, min_char_size);
		    long length_in_bytes;
		    if (current_index == index) {
			if (min_char_size > converted_width) {
			    length_in_bytes = converted_width;
			}
			else {
			    length_in_bytes = min_char_size;
			}
			ucnv_close(cnv);
			return str_new_copy_of_part(self, offset_in_bytes, length_in_bytes);
		    }
		    else if (current_index + diff > index) {
			long adjusted_offset = offset_in_bytes + (index - current_index) * min_char_size;
			if (adjusted_offset + min_char_size > offset_in_bytes + converted_width) {
			    length_in_bytes = offset_in_bytes + converted_width - adjusted_offset;
			}
			else {
			    length_in_bytes = min_char_size;
			}
			ucnv_close(cnv);
			return str_new_copy_of_part(self, adjusted_offset, length_in_bytes);
		    }
		    current_index += diff;
		}
		else {
		    if (ucs2_mode && !U_IS_BMP(c)) {
			if (((current_index == index) || (current_index+1 == index))) {
			    // you can't cut a surrogate in an encoding that is not UTF-16
			    // (it's in theory possible to store the surrogate in
			    //  UTF-8 or UTF-32 but that would be incorrect Unicode)
			    str_cannot_cut_surrogate();
			}
			++current_index;
		    }

		    if (current_index == index) {
			ucnv_close(cnv);
			return str_new_copy_of_part(self, offset_in_bytes, converted_width);
		    }

		    ++current_index;
		}
	    }
	}
    }
}

static string_t *
str_plus_string(string_t *str1, string_t *str2)
{
    encoding_t *new_encoding = str_must_have_compatible_encoding(str1, str2);

    string_t *new_str = str_alloc();
    new_str->encoding = new_encoding;
    if ((str1->length_in_bytes == 0) && (str2->length_in_bytes == 0)) {
	return new_str;
    }

    bool str1_in_uchars = str_is_stored_in_uchars(str1);
    bool str2_in_uchars = str_is_stored_in_uchars(str2);

    if (str1_in_uchars != str2_in_uchars) {
	if (str_try_making_data_uchars(str1) && str_try_making_data_uchars(str2)) {
	    str1_in_uchars = str2_in_uchars = true;
	}
	else {
	    str_make_data_binary(str1);
	    str_make_data_binary(str2);
	    str1_in_uchars = str2_in_uchars = false;
	}
    }

    str_set_stored_in_uchars(new_str, str1_in_uchars);
    long length_in_bytes = str1->length_in_bytes + str2->length_in_bytes;
    new_str->data.bytes = xmalloc(length_in_bytes);
    if (str1->length_in_bytes > 0) {
	memcpy(new_str->data.bytes, str1->data.bytes, str1->length_in_bytes);
    }
    if (str2->length_in_bytes > 0) {
	memcpy(new_str->data.bytes + str1->length_in_bytes, str2->data.bytes, str2->length_in_bytes);
    }
    new_str->capacity_in_bytes = new_str->length_in_bytes = length_in_bytes;

    return new_str;
}

static void
str_concat_string(string_t *self, string_t *str)
{
    if (str->length_in_bytes == 0) {
	return;
    }
    if (self->length_in_bytes == 0) {
	str_replace(self, (VALUE)str);
	return;
    }

    str_must_have_compatible_encoding(self, str);

    if (str_is_stored_in_uchars(self) != str_is_stored_in_uchars(str)) {
	// we try not to change the internal format of self if it's possible
	// (because self is generally bigger that the string concatenated)
	if (str_is_stored_in_uchars(self)) {
	    if (!str_try_making_data_uchars(str)) {
		str_make_data_binary(self);
	    }
	}
	else {
	    str_make_data_binary(str);
	}
    }

    long new_length_in_bytes = self->length_in_bytes + str->length_in_bytes;
    // TODO: we should maybe merge flags
    // (if both are ASCII-only, the concatenation is ASCII-only,
    //  though I'm not sure all the tests required are worth doing)
    str_unset_facultative_flags(self);
    if (self->capacity_in_bytes < new_length_in_bytes) {
	uint8_t *bytes = xmalloc(new_length_in_bytes);
	memcpy(bytes, self->data.bytes, self->length_in_bytes);
	GC_WB(&self->data.bytes, bytes);
	self->capacity_in_bytes = new_length_in_bytes;
    }
    memcpy(self->data.bytes + self->length_in_bytes, str->data.bytes, str->length_in_bytes);
    self->length_in_bytes = new_length_in_bytes;
}

static bool
str_is_equal_to_string(string_t *self, string_t *str)
{
    if (self == str) {
	return true;
    }

    if (self->length_in_bytes == 0) {
	if (str->length_in_bytes == 0) {
	    // both strings are empty
	    return true;
	}
	else {
	    // only self is empty
	    return false;
	}
    }
    else if (str->length_in_bytes == 0) {
	// only str is empty
	return false;
    }

    if (str_compatible_encoding(self, str) != NULL) {
	if (str_is_stored_in_uchars(self) == str_is_stored_in_uchars(str)) {
	    if (self->length_in_bytes != str->length_in_bytes) {
		return false;
	    }
	    else {
		return (memcmp(self->data.bytes, str->data.bytes, self->length_in_bytes) == 0);
	    }
	}
	else { // one is in uchars and the other is in binary
	    if (!str_try_making_data_uchars(self) || !str_try_making_data_uchars(str)) {
		// one is in uchars but the other one can't be converted in uchars
		return false;
	    }
	    if (self->length_in_bytes != str->length_in_bytes) {
		return false;
	    }
	    else {
		return (memcmp(self->data.bytes, str->data.bytes, self->length_in_bytes) == 0);
	    }
	}
    }
    else { // incompatible encodings
	return false;
    }
}

//----------------------------------------------
// Functions called by MacRuby

static VALUE
mr_enc_s_is_compatible(VALUE klass, SEL sel, VALUE str1, VALUE str2)
{
    assert(OBJC_CLASS(str1) == rb_cMRString);
    assert(OBJC_CLASS(str2) == rb_cMRString);
    encoding_t *encoding = str_compatible_encoding(STR(str1), STR(str2));
    if (encoding == NULL) {
	return Qnil;
    }
    else {
	return (VALUE)encoding;
    }
}


static VALUE
mr_str_initialize(VALUE self, SEL sel, int argc, VALUE *argv)
{
    if (argc > 0) {
	assert(argc == 1);
	str_replace(STR(self), argv[0]);
    }
    return self;
}

static VALUE
mr_str_replace(VALUE self, SEL sel, VALUE arg)
{
    str_replace(STR(self), arg);
    return self;
}

static VALUE
mr_str_clear(VALUE self, SEL sel)
{
    str_clear(STR(self));
    return self;
}

static VALUE
mr_str_chars_count(VALUE self, SEL sel)
{
    return INT2NUM(str_length(STR(self), false));
}

static VALUE
mr_str_length(VALUE self, SEL sel)
{
    return INT2NUM(str_length(STR(self), true));
}

static VALUE
mr_str_bytesize(VALUE self, SEL sel)
{
    return INT2NUM(str_bytesize(STR(self)));
}

static VALUE
mr_str_encoding(VALUE self, SEL sel)
{
    return (VALUE)STR(self)->encoding;
}

static VALUE
mr_str_getbyte(VALUE self, SEL sel, VALUE index)
{
    unsigned char c;
    if (str_getbyte(STR(self), NUM2LONG(index), &c)) {
	return INT2NUM(c);
    }
    else {
	return Qnil;
    }
}

static VALUE
mr_str_setbyte(VALUE self, SEL sel, VALUE index, VALUE value)
{
    str_setbyte(STR(self), NUM2LONG(index), 0xFF & (unsigned long)NUM2LONG(value));
    return value;
}

static VALUE
mr_str_force_encoding(VALUE self, SEL sel, VALUE encoding)
{
    encoding_t *enc;
    if (OBJC_CLASS(encoding) == rb_cMREncoding) {
	enc = (encoding_t *)encoding;
    }
    else {
	abort(); // TODO
    }
    str_force_encoding(STR(self), enc);
    return self;
}

static VALUE
mr_str_is_valid_encoding(VALUE self, SEL sel)
{
    return str_is_valid_encoding(STR(self)) ? Qtrue : Qfalse;
}

static VALUE
mr_str_is_ascii_only(VALUE self, SEL sel)
{
    return str_is_ruby_ascii_only(STR(self)) ? Qtrue : Qfalse;
}

static VALUE
mr_str_aref(VALUE self, SEL sel, int argc, VALUE *argv)
{
    if (argc == 1) {
	VALUE index = argv[0];
	switch (TYPE(index)) {
	    case T_FIXNUM:
		{
		    string_t *ret = str_get_character_at(STR(self), FIX2LONG(index), true);
		    if (ret == NULL) {
			return Qnil;
		    }
		    else {
			return (VALUE)ret;
		    }
		}
	}
	abort(); // TODO
    }
    else if (argc == 2) {
	long length = NUM2LONG(argv[1]);
	if (length < 0) {
	    return Qnil;
	}
	long start = NUM2LONG(argv[0]);
	long end = start + length;
	if ((start < 0) && (end >= 0)) {
	    end = -1;
	}
	string_t *ret = str_get_characters(STR(self), start, end, true);
	if (ret == NULL) {
	    return Qnil;
	}
	else {
	    return (VALUE)ret;
	}
    }
    else {
	rb_raise(rb_eArgError, "wrong number of arguments (%d for 1)", argc);
    }
}

static VALUE
mr_str_getchar(VALUE self, SEL sel, VALUE index)
{
    string_t *ret = str_get_character_at(STR(self), FIX2LONG(index), false);
    if (ret == NULL) {
	return Qnil;
    }
    else {
	return (VALUE)ret;
    }
}

static VALUE
mr_str_plus(VALUE self, SEL sel, VALUE str)
{
    if (OBJC_CLASS(str) != rb_cMRString) {
	abort(); // TODO
    }
    return (VALUE)str_plus_string(STR(self), STR(str));
}

static VALUE
mr_str_concat(VALUE self, SEL sel, VALUE str)
{
    if (OBJC_CLASS(str) != rb_cMRString) {
	abort(); // TODO (should also accept integers)
    }
    str_concat_string(STR(self), STR(str));
    return self;
}

static VALUE
mr_str_equal(VALUE self, SEL sel, VALUE str)
{
    if (OBJC_CLASS(str) != rb_cMRString) {
	abort(); // TODO
    }
    return str_is_equal_to_string(STR(self), STR(str)) ? Qtrue : Qfalse;
}

static VALUE
mr_str_not_equal(VALUE self, SEL sel, VALUE str)
{
    if (OBJC_CLASS(str) != rb_cMRString) {
	abort(); // TODO
    }
    return str_is_equal_to_string(STR(self), STR(str)) ? Qfalse : Qtrue;
}

static VALUE
mr_str_is_stored_in_uchars(VALUE self, SEL sel)
{
    return str_is_stored_in_uchars(STR(self)) ? Qtrue : Qfalse;
}

void
Init_MRString(void)
{
    // encodings must be loaded before strings
    assert((default_external != NULL) && (default_internal != NULL));

    rb_cMRString = rb_define_class("MRString", rb_cObject);
    rb_objc_define_method(OBJC_CLASS(rb_cMRString), "alloc", mr_str_s_alloc, 0);

    rb_objc_define_method(rb_cMRString, "initialize", mr_str_initialize, -1);
    rb_objc_define_method(rb_cMRString, "initialize_copy", mr_str_replace, 1);
    rb_objc_define_method(rb_cMRString, "replace", mr_str_replace, 1);
    rb_objc_define_method(rb_cMRString, "clear", mr_str_clear, 0);
    rb_objc_define_method(rb_cMRString, "encoding", mr_str_encoding, 0);
    rb_objc_define_method(rb_cMRString, "length", mr_str_length, 0);
    rb_objc_define_method(rb_cMRString, "size", mr_str_length, 0); // alias
    rb_objc_define_method(rb_cMRString, "bytesize", mr_str_bytesize, 0);
    rb_objc_define_method(rb_cMRString, "getbyte", mr_str_getbyte, 1);
    rb_objc_define_method(rb_cMRString, "setbyte", mr_str_setbyte, 2);
    rb_objc_define_method(rb_cMRString, "force_encoding", mr_str_force_encoding, 1);
    rb_objc_define_method(rb_cMRString, "valid_encoding?", mr_str_is_valid_encoding, 0);
    rb_objc_define_method(rb_cMRString, "ascii_only?", mr_str_is_ascii_only, 0);
    rb_objc_define_method(rb_cMRString, "[]", mr_str_aref, -1);
    rb_objc_define_method(rb_cMRString, "+", mr_str_plus, 1);
    rb_objc_define_method(rb_cMRString, "<<", mr_str_concat, 1);
    rb_objc_define_method(rb_cMRString, "concat", mr_str_concat, 1);
    rb_objc_define_method(rb_cMRString, "==", mr_str_equal, 1);
    rb_objc_define_method(rb_cMRString, "!=", mr_str_not_equal, 1);

    // added for MacRuby
    rb_objc_define_method(rb_cMRString, "chars_count", mr_str_chars_count, 0);
    rb_objc_define_method(rb_cMRString, "getchar", mr_str_getchar, 1);

    // this method does not exist in Ruby and is there only for debugging purpose
    rb_objc_define_method(rb_cMRString, "stored_in_uchars?", mr_str_is_stored_in_uchars, 0);
}

void
Init_new_string(void)
{
    Init_MREncoding();
    Init_MRString();
}
