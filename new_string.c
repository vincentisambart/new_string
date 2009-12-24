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
// - free strings memory

VALUE rb_cMREncoding;

typedef struct {
    struct RBasic basic;
    unsigned int index;
    const char *public_name;
    unsigned int fixed_size;
    bool ascii_compatible;
    const char **aliases;
    unsigned int aliases_count;
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
    ENCODING_EUCJP,
    ENCODING_SJIS,
    ENCODING_CP932,

    ENCODINGS_COUNT
};

#if __LITTLE_ENDIAN__
#define ENCODING_UTF16_NATIVE ENCODING_UTF16LE
#define ENCODING_UTF32_NATIVE ENCODING_UTF32LE
#else
#define ENCODING_UTF16_NATIVE ENCODING_UTF16BE
#define ENCODING_UTF32_NATIVE ENCODING_UTF32BE
#endif

static encoding_t *encodings[ENCODINGS_COUNT];

static VALUE mr_enc_s_list(VALUE klass, SEL sel)
{
    VALUE ary = rb_ary_new2(ENCODINGS_COUNT);
    for (unsigned int i = 0; i < ENCODINGS_COUNT; ++i) {
	rb_ary_push(ary, (VALUE)encodings[i]);
    }
    return ary;
}

static VALUE mr_enc_s_name_list(VALUE klass, SEL sel)
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

static VALUE mr_enc_s_aliases(VALUE klass, SEL sel)
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

static VALUE mr_enc_s_default_internal(VALUE klass, SEL sel)
{
    return (VALUE)default_internal;
}

static VALUE mr_enc_s_default_external(VALUE klass, SEL sel)
{
    return (VALUE)default_external;
}

static VALUE mr_enc_name(VALUE self, SEL sel)
{
    return rb_str_new2(ENC(self)->public_name);
}

static VALUE mr_enc_inspect(VALUE self, SEL sel)
{
    return rb_sprintf("#<%s:%s>", rb_obj_classname(self), ENC(self)->public_name);
}

static VALUE mr_enc_names(VALUE self, SEL sel)
{
    encoding_t *encoding = ENC(self);

    VALUE ary = rb_ary_new2(encoding->aliases_count + 1);
    rb_ary_push(ary, rb_str_new2(encoding->public_name));
    for (unsigned int i = 0; i < encoding->aliases_count; ++i) {
	rb_ary_push(ary, rb_str_new2(encoding->aliases[i]));
    }
    return ary;
}

static VALUE mr_enc_ascii_compatible_p(VALUE self, SEL sel)
{
    return ENC(self)->ascii_compatible ? Qtrue : Qfalse;
}

static VALUE mr_enc_dummy_p(VALUE self, SEL sel)
{
    return Qfalse;
}

static void define_encoding_constant(const char *name, encoding_t *enc)
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

static void add_encoding(
	unsigned int encoding_index, // index of the encoding in the encodings array
	const char *public_name, // public name for the encoding
	unsigned int fixed_size, // if 0 the size of a character is not fixed, if 1 or more it's the size of a character (in bytes)
	const bool ascii_compatible, // is the encoding ASCII compatible or not
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
    enc->fixed_size = fixed_size;
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

static void create_encodings(void)
{
    add_encoding(ENCODING_BINARY,    "ASCII-8BIT",  1, true,  "BINARY", NULL);
    add_encoding(ENCODING_ASCII,     "US-ASCII",    1, true,  "ASCII", "ANSI_X3.4-1968", "646", NULL);
    add_encoding(ENCODING_UTF8,      "UTF-8",       0, true,  "CP65001", NULL);
    add_encoding(ENCODING_UTF16BE,   "UTF-16BE",    0, false, NULL);
    add_encoding(ENCODING_UTF16LE,   "UTF-16LE",    0, false, NULL);
    add_encoding(ENCODING_UTF32BE,   "UTF-32BE",    4, false, "UCS-4BE", NULL);
    add_encoding(ENCODING_UTF32LE,   "UTF-32LE",    4, false, "UCS-4LE", NULL);
    add_encoding(ENCODING_ISO8859_1, "ISO-8859-1",  1, true,  "ISO8859-1", NULL);
    // FIXME: the ICU conversion tables do not seem to match Ruby's Japanese conversion tables
    add_encoding(ENCODING_EUCJP,     "EUC-JP",      0, true,  "eucJP", NULL);
    add_encoding(ENCODING_SJIS,      "Shift_JIS",   0, true, "SJIS", NULL);
    add_encoding(ENCODING_CP932,     "Windows-31J", 0, true, "CP932", "csWindows31J", NULL);

    default_external = encodings[ENCODING_UTF8];
    default_internal = encodings[ENCODING_UTF16LE];
}

void Init_MREncoding(void)
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
    //rb_define_singleton_method(rb_cMREncoding, "compatible?", enc_compatible_p, 2);

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

// In binary representation, the length and capacity are in bytes.
// In UTF-16 representation, the length and capacity are in UChars
// (so len might be bigger than the length of the string in Unicode code points)
typedef struct {
    struct RBasic basic;
    encoding_t *enc;
    long capa;
    long len;
    union {
	char *bytes;
	UChar *uchars;
    } data;
    bool is_utf16 : 1;
} string_t;

#define STR(x) ((string_t *)(x))

// do not forget to close the converter
// before leaving the function
#define USE_CONVERTER(cnv, str) \
    char cnv##_buffer[U_CNV_SAFECLONE_BUFFERSIZE]; \
    UErrorCode cnv##_err = U_ZERO_ERROR; \
    int32_t cnv##_buffer_size = U_CNV_SAFECLONE_BUFFERSIZE; \
    UConverter *cnv = ucnv_safeClone( \
	    str->enc->converter, \
	    cnv##_buffer, \
	    &cnv##_buffer_size, \
	    &cnv##_err \
	); \
    ucnv_reset(cnv);

static string_t *str_alloc(void)
{
    NEWOBJ(str, string_t);
    str->basic.flags = 0;
    str->basic.klass = rb_cMRString;
    str->enc = encodings[ENCODING_BINARY];
    str->capa = 0;
    str->len = 0;
    str->data.bytes = 0;
    str->is_utf16 = false;
    return str;
}

static VALUE mr_str_s_alloc(VALUE klass)
{
    return (VALUE)str_alloc();
}

extern VALUE rb_cString;
extern VALUE rb_cCFString;
extern VALUE rb_cNSString;
extern VALUE rb_cNSMutableString;
extern VALUE rb_cSymbol;
extern VALUE rb_cByteString;

static string_t *str_replace(string_t *self, VALUE arg)
{
    if (self->data.bytes != NULL) {
	free(self->data.bytes);
	self->data.bytes = NULL;
	self->len = 0;
	self->capa = 0;
    }

    VALUE klass = OBJC_CLASS(arg);
    if (klass == rb_cByteString) {
	self->enc = encodings[ENCODING_BINARY];
	self->capa = self->len = rb_bytestring_length(arg);
	if (self->len != 0) {
	    self->data.bytes = malloc(self->len);
	    assert(self->data.bytes != NULL);
	    memcpy(self->data.bytes, rb_bytestring_byte_pointer(arg), self->len);
	}
    }
    else if ((klass == rb_cString)
		|| (klass == rb_cCFString)
		|| (klass == rb_cNSString)
		|| (klass == rb_cNSMutableString)) {
	self->enc = encodings[ENCODING_UTF16_NATIVE];
	self->capa = self->len = CFStringGetLength((CFStringRef)arg);
	self->is_utf16 = true;
	if (self->len != 0) {
	    self->data.uchars = malloc(self->len * sizeof(UChar));
	    assert(self->data.uchars != NULL);
	    CFStringGetCharacters((CFStringRef)arg, CFRangeMake(0, self->len), self->data.uchars);
	}
    }
    else if (klass == rb_cMRString) {
	string_t *str = STR(arg);
	self->enc = str->enc;
	self->capa = self->len = str->len;
	self->is_utf16 = str->is_utf16;
	if (self->len != 0) {
	    if (str->is_utf16) {
		self->data.uchars = malloc(self->len * sizeof(UChar));
		assert(self->data.uchars != NULL);
		memcpy(self->data.uchars, str->data.uchars, self->len * sizeof(UChar));
	    }
	    else {
		self->data.bytes = malloc(self->len);
		assert(self->data.bytes != NULL);
		memcpy(self->data.bytes, str->data.bytes, self->len);
	    }
	}
    }
    else if (klass == rb_cSymbol) {
	abort(); // TODO
    }
    else {
	abort(); // TODO
    }
    return self;
}

static long str_length(string_t *self)
{
    if (self->is_utf16) {
	// we must return the length in Unicode code points,
	// not the number of UChars, even if the probability
	// we have surrogates is very low
	return u_countChar32(self->data.uchars, self->len);
    }
    else {
	if (self->enc->fixed_size > 0) {
	    return self->len;
	}
	else {
	    USE_CONVERTER(cnv, self);

	    const char *pos = self->data.bytes;
	    const char *end = pos + self->len;
	    long len = 0;
	    for (;;) {
		// iterate through the string one Unicode code point at a time
		// (we dont care what the character is or if it's valid or not)
		UErrorCode err = U_ZERO_ERROR;
		ucnv_getNextUChar(cnv, &pos, end, &err);
		if (err == U_INDEX_OUTOFBOUNDS_ERROR) {
		    // end of the string
		    break;
		}
		++len;
	    }

	    ucnv_close(cnv);
	    return len;
	}
    }
}

#define STACK_BUFFER_SIZE 1024
static long str_bytesize(string_t *self)
{
    if (self->is_utf16) {
	if ((self->enc == encodings[ENCODING_UTF16BE])
		|| (self->enc == encodings[ENCODING_UTF16LE])) {
	    return self->len * sizeof(UChar);
	}
	else {
	    // for strings stored in UTF-16 for which the Ruby encoding is not UTF-16,
	    // calculate the length this string would have if it was in this encoding
	    USE_CONVERTER(cnv, self);

	    long len = 0;
	    char buffer[STACK_BUFFER_SIZE];
	    const UChar *source_pos = self->data.uchars;
	    const UChar *source_end = self->data.uchars + self->len;
	    char *target_end = buffer + STACK_BUFFER_SIZE;
	    UErrorCode err = U_ZERO_ERROR;
	    for (;;) {
		char *target_pos = buffer;
		ucnv_fromUnicode(cnv, &target_pos, target_end, &source_pos, source_end, NULL, true, &err);
		len += target_pos - buffer;
		if (err != U_BUFFER_OVERFLOW_ERROR) {
		    assert(U_SUCCESS(err));
		    break;
		}
	    }

	    ucnv_close(cnv);
	    return len;
	}
    }
    else {
	return self->len;
    }
}

static VALUE mr_str_initialize(VALUE self, SEL sel, int argc, VALUE *argv)
{
    VALUE arg;
    if (argc > 0) {
	rb_scan_args(argc, argv, "01", &arg);
	str_replace(STR(self), arg);
    }
    return self;
}

static VALUE mr_str_length(VALUE self, SEL sel)
{
    return INT2NUM(str_length(STR(self)));
}

static VALUE mr_str_bytesize(VALUE self, SEL sel)
{
    return INT2NUM(str_bytesize(STR(self)));
}

static VALUE mr_str_encoding(VALUE self, SEL sel)
{
    return (VALUE)STR(self)->enc;
}

void Init_MRString(void)
{
    // encodings must be loaded before strings
    assert((default_external != NULL) && (default_internal != NULL));

    rb_cMRString = rb_define_class("MRString", rb_cObject);
    rb_objc_define_method(OBJC_CLASS(rb_cMRString), "alloc", mr_str_s_alloc, 0);

    rb_objc_define_method(rb_cMRString, "initialize", mr_str_initialize, -1);
    rb_objc_define_method(rb_cMRString, "encoding", mr_str_encoding, 0);
    rb_objc_define_method(rb_cMRString, "length", mr_str_length, 0);
    rb_objc_define_method(rb_cMRString, "bytesize", mr_str_bytesize, 0);
}

void Init_new_string(void)
{
    Init_MREncoding();
    Init_MRString();
}
