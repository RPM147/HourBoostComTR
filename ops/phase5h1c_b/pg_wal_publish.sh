# PostgreSQL archive_command. Fixed private bind, no replace, no pruning.
set -euo pipefail
export LC_ALL=C
umask 077
dest=/run/hourboost-wal
data=/var/lib/postgresql/data
[[ $# == 3 && $3 =~ ^[0-9]+:[0-9]+$ && $(id -u):$(id -g) == 999:999 ]]
src=$1; wal=$2
[[ $wal =~ ^([0-9A-F]{24}(\.[0-9A-F]{8}\.backup)?|[0-9A-F]{8}\.history)$ && $src == "pg_wal/$wal" ]]
[[ $(pwd -P) == "$data" && ! -L pg_wal && -f $src && ! -L $src ]]
[[ -d $dest && ! -L $dest && $(stat -c '%d:%i:%u:%g:%a' "$dest") == "$3:999:999:700" ]]
[[ $(stat -c %d "$dest") == "$(stat -c %d .)" && $(stat -f -c %t "$dest") == ef53 ]]
size=$(stat -c %s "$src")
if [[ $wal =~ ^[0-9A-F]{24}$ ]]; then [[ $size == 16777216 ]]; else (( size > 0 && size <= 1048576 )); fi
out=$dest/$wal
verify_existing() {
    [[ ! -L $out && -f $out && $(stat -c '%u:%g:%a' "$out") == 999:999:600 ]] &&
        cmp -s -- "$src" "$out" && sync -- "$out" "$dest"
}
if [[ -e $out || -L $out ]]; then verify_existing; exit $?; fi
tmp=$(mktemp -- "$dest/.incoming.XXXXXXXXXX")
trap 'rm -f -- "$tmp"' EXIT
# Copy instead of linking a PostgreSQL segment that the server could recycle.
cp --reflink=never -- "$src" "$tmp"
cmp -s -- "$src" "$tmp"
sync -- "$tmp"
# link(2) publishes without overwriting, including when two attempts race.
if ! ln -T -- "$tmp" "$out"; then verify_existing; fi
rm -- "$tmp"; trap - EXIT
sync -- "$dest"
