require 'mkmf'

$INCFLAGS << ' -I../..'
$CFLAGS << ' -g -std=c99'
$LDFLAGS << ' -licucore'
create_makefile('new_string')
