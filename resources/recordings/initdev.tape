# GIF — admina -> admina init -> admina dev (resources/admina-init-dev.gif)
# Run from resources/recordings/ :  vhs initdev.tape
Output "../admina-init-dev.gif"

Set Shell "zsh"
Set FontSize 15
Set Width 1280
Set Height 720
Set Padding 20
Set TypingSpeed 35ms

Hide
Type 'ADMINA_BIN=$(uv run --no-sync which admina 2>/dev/null)'
Enter
Type 'admina() { [ $# -eq 0 ] && { "$ADMINA_BIN"; return; }; script -q /dev/null "$ADMINA_BIN" "$@" | tr -d "\r" | sed -lE "s/(API Key:|Password:)([[:space:]]+)[^ ]+/\1\2********  (saved to .env)/" | grep --line-buffered -vE "INFO|WARNING|GET |WebSocket|connection (open|closed|rejected)|Forbidden"; }'
Enter
Type 'workdir=$(mktemp -d) && cd "$workdir" && clear'
Enter
Show

Type 'admina'
Sleep 500ms
Enter
Sleep 3500ms
Hide
Type 'clear'
Enter
Show

Type 'admina init demo --full-stack --no-pull'
Sleep 700ms
Enter
Sleep 5s
Type 'cd demo && admina dev --no-browser'
Sleep 700ms
Enter
Sleep 7s
Ctrl+C
Sleep 1500ms
