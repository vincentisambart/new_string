#ifndef __ENCODING_H_
#define __ENCODING_H_

#if defined(__cplusplus)
extern "C" {
#endif

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

extern encoding_t *encodings[ENCODINGS_COUNT];

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

#define NATIVE_UTF16_ENC(encoding) ((encoding) == encodings[ENCODING_UTF16_NATIVE])
#define NON_NATIVE_UTF16_ENC(encoding) ((encoding) == encodings[ENCODING_UTF16_NON_NATIVE])
#define UTF16_ENC(encoding) (NATIVE_UTF16_ENC(encoding) || NON_NATIVE_UTF16_ENC(encoding))
#define NATIVE_UTF32_ENC(encoding) ((encoding) == encodings[ENCODING_UTF32_NATIVE])
#define NON_NATIVE_UTF32_ENC(encoding) ((encoding) == encodings[ENCODING_UTF32_NON_NATIVE])
#define UTF32_ENC(encoding) (NATIVE_UTF32_ENC(encoding) || NON_NATIVE_UTF32_ENC(encoding))
#define BINARY_ENC(encoding) ((encoding) == encodings[ENCODING_BINARY])

typedef struct {
    long start_offset_in_bytes;
    long end_offset_in_bytes;
} character_boundaries_t;

typedef struct {
    void (*update_flags)(string_t *);
    void (*make_data_binary)(string_t *);
    bool (*try_making_data_uchars)(string_t *);
    long (*length)(string_t *);
    long (*bytesize)(string_t *);
    character_boundaries_t (*get_character_boundaries)(string_t *, long, bool);
} encoding_methods_t;

typedef struct {
    struct RBasic basic;
    unsigned int index;
    const char *public_name;
    const char **aliases;
    unsigned int aliases_count;
    unsigned char min_char_size;
    bool single_byte_encoding : 1;
    bool ascii_compatible : 1;
    encoding_methods_t methods;
    void *private_data;
} encoding_t;

extern VALUE rb_cMREncoding;

#if defined(__cplusplus)
}
#endif

#endif /* __ENCODING_H_ */
