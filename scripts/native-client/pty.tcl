# macOS ships Expect. Bridge pipes to its child PTY without requiring a host TTY.
log_user 0
fconfigure stdin -blocking 0 -translation binary -encoding binary
fconfigure stdout -translation binary -encoding binary
spawn -noecho /bin/bash -c {stty rows 40 cols 120; test -t 0 && test -t 1 || exit 90; printf '\033[2J\033[Hnative-fixture PTY verified pid=%s\r\n' "$$"; exec "$@"} native-fixture {*}$argv
set child $spawn_id
fconfigure $child -translation binary -encoding binary
match_max -i $child 4096
fileevent stdin readable {
    set data [read stdin 65536]
    if {[string length $data]} {send -i $child -- $data}
    if {[eof stdin]} {fileevent stdin readable {}}
}
expect_background -i $child -re {(?s).+} {
    puts -nonewline stdout $expect_out(0,string); flush stdout
} eof {
    set result [wait -i $child]
    if {[lindex $result 2] != 0 || [lindex $result 4] eq "CHILDKILLED"} {exit 125}
    exit [lindex $result 3]
}
vwait forever
