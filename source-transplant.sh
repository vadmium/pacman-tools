# Catch naive references to host file system; specifically the
# "kernel26.preset" script refers to the "kernel26.kver" script with
# an absolute name
source() {
    case "$1" in
    /*) command source "$BASEDIR$@";;
    *) command source "$@";;
    esac
}
