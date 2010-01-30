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
def assert_equal(wanted, got, line_no = called_line)
  $tests_done_count += 1
  wanted = S.new(wanted) if MACRUBY and wanted.instance_of?(NSMutableString)
  got = S.new(got) if MACRUBY and got.instance_of?(NSMutableString)
  if wanted != got
    $tests_failed_count += 1
    puts "test failed: #{wanted.inspect} != #{got.inspect} at line #{line_no} (encoding: #{$current_encoding.name})"
  end
end

def assert_not_equal(not_wanted, got, line_no = called_line)
  $tests_done_count += 1
  wanted = S.new(wanted) if MACRUBY and wanted.instance_of?(NSMutableString)
  got = S.new(got) if MACRUBY and got.instance_of?(NSMutableString)
  if not_wanted == got
    $tests_failed_count += 1
    puts "test failed: #{not_wanted.inspect} == #{got.inspect} at line #{line_no} (encoding: #{$current_encoding.name})"
  end
end

def assert_no_exception_raised(line_no = called_line)
  $tests_done_count += 1
  begin
    yield
  rescue Exception
    $tests_failed_count += 1
    puts "test failed: exception raised at line #{line_no} (encoding: #{$current_encoding.name})"
  end
end

def assert_exception_raised(exception, line_no = called_line)
  $tests_done_count += 1
  begin
    yield
  rescue exception
    # we got the exception we wanted
  else
    $tests_failed_count += 1
    puts "test failed: exception #{exception.name} not raised at line #{line_no} (encoding: #{$current_encoding.name})"
  end
end

UNICODE_ENCODINGS.each do |enc|
  data = read_data('ohayougozaimasu', enc)

  if enc == :UTF_16LE
    assert_equal utf16le('お'), data[0]
  else
    assert_not_equal utf16le('お'), data[0]
  end

  assert_equal 9, data.length
  assert_equal 9, data.chars_count if MACRUBY
  data.length.times do |i|
    c = data[i]
    assert_equal data.encoding, c.encoding
    assert_equal 1, c.length
    assert_equal 1, c.chars_count if MACRUBY
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
end

SURROGATE_UTF16_BYTES = [0xD8, 0x40, 0xDC, 0x0B]
UNICODE_ENCODINGS.each do |enc|
  data = read_data('surrogate', enc)

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
    assert_equal 2, data.length, __LINE__
    data.length.times do |i|
      if enc == :UTF_16LE or enc == :UTF_16BE
        assert_no_exception_raised(__LINE__) { data[i] }
        c = data[i]
        assert_not_equal nil, c, __LINE__
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
    assert_no_exception_raised(__LINE__) { data[2] }
  end
  assert_equal 2, chars_count(data)
end

UNICODE_ENCODINGS.each do |enc|
  data = read_data('cut', enc)

  assert_equal false, data.valid_encoding?
  assert_equal false, data[-1].valid_encoding?
  if enc == :UTF_8
    assert_equal 10, data.length
    assert_equal 10, data.chars_count if MACRUBY
    c1, c2 = data[8], data[9]
    assert_equal 1, c1.length
    assert_equal 1, c1.bytesize
    assert_equal 0xE3, c1.getbyte(0)
    assert_equal 1, c2.length
    assert_equal 1, c2.bytesize
    assert_equal 0x81, c2.getbyte(0)
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
  assert_equal 8, data.bytesize
  assert_equal false, data.valid_encoding?
  #assert_equal 1, (data[1]+data[0]).length # for when we support +

  if MACRUBY
    assert_equal 4, data.length, __LINE__
    assert_equal 2, data[0].bytesize, __LINE__
    assert_equal 2, data[1].bytesize, __LINE__
    assert_equal 2, data[2].bytesize, __LINE__
    assert_equal 2, data[3].bytesize, __LINE__
    assert_equal nil, data[4], __LINE__
    assert_equal nil, data[-5], __LINE__
    assert_equal 2, data[-4].bytesize, __LINE__
    assert_equal 2, data[-3].bytesize, __LINE__
    assert_equal 2, data[-2].bytesize, __LINE__
    assert_equal 2, data[-1].bytesize, __LINE__
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

if $tests_failed_count == 0
  puts "everything's fine"
else
  puts "#{$tests_failed_count}/#{$tests_done_count} tests failed"
end
