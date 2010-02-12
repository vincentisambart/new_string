require 'mkmf'

$CFLAGS << ' -g -std=c99 -Werror'
$LDFLAGS << ' -licucore'
create_makefile('new_string')
