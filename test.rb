MACRUBY = defined?(MACRUBY_VERSION)

if MACRUBY
  require 'new_string'
  S = MRString
  E = MREncoding
else
  S = String
  E = Encoding
end

UNICODE_ENCODINGS = [:UTF_8, :UTF_16BE, :UTF_16LE, :UTF_32BE, :UTF_32BE]

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

$tests_done_count = 0
$tests_failed_count = 0
def assert_equal(wanted, got)
  $tests_done_count += 1
  if wanted != got
    $tests_failed_count += 1
    begin
      raise ''
    rescue Exception => e
      bt = e.backtrace
      md = /:(\d+):/.match(bt[-1])
      puts "test failed: #{wanted} != #{got} at line #{md[1]}"
    end
  end
end

UNICODE_ENCODINGS.each do |enc|
  data = read_data('ohayougozaimasu', enc)

  assert_equal 9, data.length
  case enc
  when :UTF_8
    assert_equal 27, data.bytesize
  when :UTF_16LE, :UTF16_BE
    assert_equal 18, data.bytesize
  when :UTF_32LE, :UTF32_BE
    assert_equal 36, data.bytesize
  end
end

if $tests_failed_count == 0
  puts "everything's fine"
else
  puts "#{$tests_failed_count}/#{$tests_done_count} tests failed"
end
