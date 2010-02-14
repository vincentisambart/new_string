# encoding: UTF-8
MACRUBY = defined?(MACRUBY_VERSION)

if MACRUBY
  require 'new_string'
  S = MRString
  E = MREncoding
else
  S = String
  E = Encoding
end

UNICODE_ENCODINGS = [:UTF_8, :UTF_16BE, :UTF_16LE, :UTF_32BE, :UTF_32LE]

def getchar(str, i)
  if MACRUBY
    str.getchar(i)
  else
    str[i]
  end
end

def chars_count(str)
  if MACRUBY
    str.chars_count
  else
    str.length
  end
end

def utf16le(str)
  if MACRUBY
    str
  else
    str.encode(Encoding::UTF_16LE)
  end
end

def read_data(name, enc_name)
  enc_for_name = enc_name.to_s.gsub(/_/, '').downcase
  file_name = File.join(File.dirname(__FILE__), "test_data/#{name}-#{enc_for_name}.txt")
  data = nil
  if MACRUBY
    data = S.new(File.read(file_name))
  else
    File.open(file_name, 'r:BINARY') do |f|
      data = f.read
    end
  end
  enc = E.const_get(enc_name)
  $current_encoding = enc
  data.force_encoding(enc)
  data
end

def called_line
  begin
    raise ''
  rescue Exception => e
    bt = e.backtrace
    md = /:(\d+):/.match(bt[2])
    return md ? md[1] : 0
  end
end

$tests_done_count = 0
$tests_failed_count = 0
def assert_equal(wanted, got)
  $tests_done_count += 1
  wanted = S.new(wanted) if MACRUBY and wanted.instance_of?(NSMutableString)
  got = S.new(got) if MACRUBY and got.instance_of?(NSMutableString)
  if wanted != got
    $tests_failed_count += 1
    puts "test failed: #{wanted.inspect} != #{got.inspect} at line #{called_line} (encoding: #{$current_encoding.name})"
  end
end

def assert_not_equal(not_wanted, got)
  $tests_done_count += 1
  wanted = S.new(wanted) if MACRUBY and wanted.instance_of?(NSMutableString)
  got = S.new(got) if MACRUBY and got.instance_of?(NSMutableString)
  if not_wanted == got
    $tests_failed_count += 1
    puts "test failed: #{not_wanted.inspect} == #{got.inspect} at line #{called_line} (encoding: #{$current_encoding.name})"
  end
end

def assert_no_exception_raised
  $tests_done_count += 1
  begin
    yield
  rescue Exception
    $tests_failed_count += 1
    puts "test failed: exception raised at line #{called_line} (encoding: #{$current_encoding.name})"
  end
end

def assert_exception_raised(exception)
  $tests_done_count += 1
  begin
    yield
  rescue exception
    # we got the exception we wanted
  else
    $tests_failed_count += 1
    puts "test failed: exception #{exception.name} not raised at line #{called_line} (encoding: #{$current_encoding.name})"
  end
end

assert_equal nil, ''[0]
assert_equal nil, ''[0, -1]
assert_equal '', ''[0, 0]
assert_equal '', ''[0, 100]
assert_equal '', ''[0..100]
assert_equal '', ''[0..0]
assert_equal '', ''[0...0]

UNICODE_ENCODINGS.each do |enc|
  data = read_data('ohayougozaimasu', enc)

  assert_equal data, S.new(data)
  assert_equal data, data.dup
  assert_equal data, data.clone

  assert_equal 9, data.length
  assert_equal 9, data.chars_count if MACRUBY
  data.length.times do |i|
    c = data[i]
    assert_equal data.encoding, c.encoding
    assert_equal 1, c.length
    assert_equal 1, c.chars_count if MACRUBY
    assert_equal true, c.valid_encoding?
  end

  assert_equal '', data[1...1]
  assert_equal '', data[9, 0]
  assert_equal nil, data[10, 0]
  assert_equal 1, data[0, 1].length
  assert_equal 2, data[0, 2].length
  if MACRUBY
    assert_equal 1, data[0, 1].chars_count
    assert_equal 2, data[0, 2].chars_count
  end

  assert_equal true, data.valid_encoding?

  case enc
  when :UTF_8
    assert_equal 27, data.bytesize
  when :UTF_16LE, :UTF_16BE
    assert_equal 18, data.bytesize
  when :UTF_32LE, :UTF_32BE
    assert_equal 36, data.bytesize
  end

  if enc == :UTF_16LE
    assert_equal utf16le('お'), data[0]
    assert_equal utf16le('お'), data[0, 1]
    assert_equal utf16le('おは'), data[0, 2]
  else
    assert_not_equal utf16le('お'), data[0]
  end
end

SURROGATE_UTF16_BYTES = [0xD8, 0x40, 0xDC, 0x0B]
UNICODE_ENCODINGS.each do |enc|
  data = read_data('surrogate', enc)

  assert_equal data, S.new(data)
  assert_equal data, data.dup
  assert_equal data, data.clone

  if enc == :UTF_16LE or enc == :UTF_16BE
    data.bytesize.times do |i|
      if enc == :UTF_16LE
        j = i.even? ? i+1 : i-1
      else
        j = i
      end
      assert_equal SURROGATE_UTF16_BYTES[j], data.getbyte(i)
    end
  end

  if MACRUBY
    assert_equal 2, data.length
    data.length.times do |i|
      if enc == :UTF_16LE or enc == :UTF_16BE
        assert_no_exception_raised { data[i] }
        c = data[i]
        assert_not_equal nil, c
        assert_equal 2, c.bytesize
        assert_equal SURROGATE_UTF16_BYTES[i*2], c.getbyte(enc == :UTF_16BE ? 0 : 1)
        assert_equal SURROGATE_UTF16_BYTES[i*2 + 1], c.getbyte(enc == :UTF_16BE ? 1 : 0)
        assert_equal false, data[i].valid_encoding?
      else
        assert_exception_raised(IndexError) { data[i] }
      end
    end
  end
  assert_equal 1, chars_count(data)
  assert_equal 4, getchar(data, 0).bytesize
  assert_equal nil, getchar(data, 1)
  assert_equal 4, data.bytesize
end

SURROGATE_WITH_INVALID_BYTES = [0x00, 0x02, 0x00, 0x0B, 0xFF, 0xFF, 0xFF, 0xFF]
[:UTF_32LE, :UTF_32BE].each do |enc|
  data = read_data('surrogate_with_invalid', enc)

  assert_equal data, S.new(data)
  assert_equal data, data.dup
  assert_equal data, data.clone

  assert_equal 8, data.bytesize
  data.bytesize.times do |i|
    if enc == :UTF_32BE
      j = i
    else
      case i%4
      when 0
        j = i + 3
      when 1
        j = i + 1
      when 2
        j = i - 1
      when 3
        j = i - 3
      end
    end
    assert_equal SURROGATE_WITH_INVALID_BYTES[j], data.getbyte(i)
  end
  if MACRUBY
    assert_equal 3, data.length
    assert_exception_raised(IndexError) { data[0] }
    assert_exception_raised(IndexError) { data[1] }
    assert_no_exception_raised { data[2] }
  end
  assert_equal 2, chars_count(data)
end

UNICODE_ENCODINGS.each do |enc|
  data = read_data('cut', enc)

  assert_equal data, S.new(data)
  assert_equal data, data.dup
  assert_equal data, data.clone

  assert_equal false, data.valid_encoding?
  assert_equal false, data[-1].valid_encoding?
  if enc == :UTF_8
    assert_equal 10, data.length
    assert_equal 10, data.chars_count if MACRUBY
    [ [data[8], data[9]],
      [data[8,1], data[9,1]],
      [data[8..8], data[9..9]],
    ].each do |c1, c2|
      assert_equal 1, c1.length
      assert_equal 1, c1.bytesize
      assert_equal 0xE3, c1.getbyte(0)
      assert_equal 1, c2.length
      assert_equal 1, c2.bytesize
      assert_equal 0x81, c2.getbyte(0)
    end
  else
    assert_equal 9, data.length
    assert_equal 9, data.chars_count if MACRUBY
  end

  case enc
  when :UTF_8
    assert_equal 26, data.bytesize
  when :UTF_16BE, :UTF_16LE
    assert_equal 17, data.bytesize

    c = data[-1]
    assert_equal 1, c.bytesize
    if enc == :UTF_16BE
      assert_equal 0x30, c.getbyte(0)
    else
      assert_equal 0x59, c.getbyte(0)
    end
  when :UTF_32BE, :UTF_32LE
    assert_equal 35, data.bytesize
  end
end

[:UTF_16LE, :UTF_16BE].each do |enc|
  data = read_data('inverted_surrogate_plus_surrogate', enc)

  assert_equal data, S.new(data)
  assert_equal data, data.dup
  assert_equal data, data.clone

  assert_equal 8, data.bytesize
  assert_equal false, data.valid_encoding?
  assert_equal 1, chars_count(data[1]+data[0])

  if MACRUBY
    assert_equal 4, data.length
    assert_equal 2, data[0].bytesize
    assert_equal 2, data[1].bytesize
    assert_equal 2, data[2].bytesize
    assert_equal 2, data[3].bytesize
    assert_equal nil, data[4]
    assert_equal nil, data[-5]
    assert_equal 2, data[-4].bytesize
    assert_equal 2, data[-3].bytesize
    assert_equal 2, data[-2].bytesize
    assert_equal 2, data[-1].bytesize
  end

  assert_equal 3, chars_count(data)
  assert_equal 2, getchar(data, 0).bytesize
  assert_equal 2, getchar(data, 1).bytesize
  assert_equal 4, getchar(data, 2).bytesize
  assert_equal nil, getchar(data, 3)
  assert_equal nil, getchar(data, -4)
  assert_equal 2, getchar(data, -3).bytesize
  assert_equal 2, getchar(data, -2).bytesize
  assert_equal 4, getchar(data, -1).bytesize
end

bonjour_ascii = read_data('bonjour', :ASCII)
bonjour_utf8 = read_data('bonjour', :ASCII).force_encoding(E::UTF_8)
bonjour_utf16le = read_data('bonjour', :UTF_16LE)
ohayou_utf8 = read_data('ohayougozaimasu', :UTF_8)
ohayou_utf16le = read_data('ohayougozaimasu', :UTF_16LE)
empty_utf8 = S.new.force_encoding(E::UTF_8)
empty_utf16le = S.new.force_encoding(E::UTF_16LE)

assert_equal true, bonjour_ascii.ascii_only?
assert_equal true, bonjour_utf8.ascii_only?
assert_equal false, bonjour_utf16le.ascii_only?
assert_equal false, ohayou_utf8.ascii_only?
assert_equal false, ohayou_utf16le.ascii_only?

assert_equal E::US_ASCII, E.compatible?(bonjour_ascii, bonjour_ascii)
assert_equal E::US_ASCII, E.compatible?(bonjour_ascii, bonjour_utf8)
assert_equal E::UTF_8, E.compatible?(bonjour_utf8, bonjour_ascii)
assert_equal E::UTF_8, E.compatible?(bonjour_utf8, bonjour_utf8)
assert_equal E::UTF_8, E.compatible?(empty_utf8, empty_utf16le)
assert_equal E::UTF_8, E.compatible?(empty_utf16le, ohayou_utf8)
assert_equal E::UTF_8, E.compatible?(ohayou_utf8, empty_utf16le)
assert_equal E::UTF_16LE, E.compatible?(empty_utf8, ohayou_utf16le)
assert_equal E::UTF_16LE, E.compatible?(ohayou_utf16le, empty_utf8)
assert_equal nil, E.compatible?(bonjour_ascii, bonjour_utf16le)
assert_equal nil, E.compatible?(bonjour_utf16le, bonjour_ascii)
assert_equal nil, E.compatible?(ohayou_utf8, ohayou_utf16le)
assert_equal nil, E.compatible?(ohayou_utf16le, ohayou_utf8)
assert_equal nil, E.compatible?(ohayou_utf8, nil)
assert_equal nil, E.compatible?(ohayou_utf8, 1)

assert_equal true, empty_utf8.valid_encoding?
assert_equal true, bonjour_utf8.force_encoding(E::BINARY).ascii_only?
assert_equal false, ohayou_utf8.force_encoding(E::BINARY).ascii_only?

assert_equal S.new('ab'), S.new('a') + S.new('b')
assert_equal S.new('b'), S.new + S.new('b')
assert_equal S.new('a'), S.new('a') + S.new
assert_equal S.new, S.new + S.new

ohayou_copy = ohayou_utf8.dup
assert_equal ohayou_utf8, ohayou_copy.replace(ohayou_copy)
assert_exception_raised(TypeError) { S.new.replace(2) }

s = empty_utf8.dup
s << empty_utf16le
assert_equal E::UTF_8, s.encoding

s = empty_utf8.dup
s << bonjour_utf16le
assert_equal E::UTF_16LE, s.encoding

s = S.new('a')
old_s = s.dup
s << S.new('')
assert_equal old_s, s
s << S.new('b')
assert_equal S.new('ab'), s
old_s = s.dup
s.concat(S.new('c'))
assert_equal S.new('abc'), s
assert_not_equal old_s, s

assert_equal empty_utf8, empty_utf16le
assert_equal bonjour_utf8, bonjour_ascii
assert_not_equal bonjour_utf16le, bonjour_ascii
assert_equal bonjour_ascii, (bonjour_ascii+bonjour_ascii)[1..-1][bonjour_ascii]

a = S.new('a')
assert_equal a, 'a'
assert_equal a, a['a']

assert_exception_raised(Encoding::CompatibilityError) { ohayou_utf8 + ohayou_utf16le }
assert_exception_raised(Encoding::CompatibilityError) { ohayou_utf8 << ohayou_utf16le }

if $tests_failed_count == 0
  puts "everything's fine"
else
  puts "#{$tests_failed_count}/#{$tests_done_count} tests failed"
end
