require 'mkmf'

$INCFLAGS << ' -I../..'
$CFLAGS << ' -g -std=c99 -Werror -fexceptions'
$LDFLAGS << ' -licucore'
create_makefile('new_string')
