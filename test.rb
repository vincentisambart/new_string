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

def read_data(name, encoding)
  enc_for_name = encoding.to_s.gsub(/_/, '').downcase
  file_name = File.join(File.dirname(__FILE__), "test_data/#{name}-#{enc_for_name}.txt")
  data = nil
  if MACRUBY
    data = S.new(File.read(file_name))
  else
    File.open(file_name, 'r:BINARY') do |f|
      data = f.read
    end
  end
  data.force_encoding(E.const_get(encoding))
  data
end

def called_line
  begin
    raise ''
  rescue Exception => e
    bt = e.backtrace
    md = /:(\d+):/.match(bt[-2])
    return md ? md[1] : 0
  end
end

$tests_done_count = 0
$tests_failed_count = 0
def assert_equal(wanted, got)
  $tests_done_count += 1
  if wanted != got
    $tests_failed_count += 1
    puts "test failed: #{wanted} != #{got} at line #{called_line}"
  end
end

def assert_no_exception_raised
  $tests_done_count += 1
  begin
    yield
  rescue Exception
    $tests_failed_count += 1
    puts "test failed: exception raised at line #{called_line}"
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
    puts "test failed: exception #{exception.name} not raised at line #{called_line}"
  end
end

UNICODE_ENCODINGS.each do |enc|
  data = read_data('ohayougozaimasu', enc)

  assert_equal 9, data.length
  data.length.times do |i|
    c = data[i]
    assert_equal data.encoding, c.encoding
    assert_equal 1, c.length
  end

  case enc
  when :UTF_8
    assert_equal 27, data.bytesize
  when :UTF_16LE, :UTF16_BE
    assert_equal 18, data.bytesize
  when :UTF_32LE, :UTF32_BE
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
    assert_equal 2, data.length
    data.length.times do |i|
      if enc == :UTF_16LE or enc == :UTF_16BE
        assert_no_exception_raised { data[i] }
        c = data[i]
        assert_equal c.bytesize, 2
        if i == 0
          assert_equal 0xD8, c.getbyte(enc == :UTF_16BE ? 0 : 1)
          assert_equal 0x40, c.getbyte(enc == :UTF_16BE ? 1 : 0)
        else
          assert_equal 0xDC, c.getbyte(enc == :UTF_16BE ? 0 : 1)
          assert_equal 0x0B, c.getbyte(enc == :UTF_16BE ? 1 : 0)
        end
        assert_equal false, data[i].valid_encoding?
      else
        assert_exception_raised(IndexError) { data[i] }
      end
    end
  else
    assert_equal 1, data.length
  end

  assert_equal 4, data.bytesize
end

if $tests_failed_count == 0
  puts "everything's fine"
else
  puts "#{$tests_failed_count}/#{$tests_done_count} tests failed"
end
