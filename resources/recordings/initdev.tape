# GIF — admina init -> admina dev (resources/admina-init-dev.gif)
# Run from resources/recordings/ :  vhs initdev.tape
Output "../admina-init-dev.gif"

Set Shell "zsh"
Set FontSize 15
Set Width 1280
Set Height 720
Set Padding 20
Set TypingSpeed 35ms

Hide
Type 'ADMINA_BIN=$(uv run which admina 2>/dev/null)'
Enter
Type 'admina() { "$ADMINA_BIN" "$@" 2>&1 | sed -lE "s/(API Key:|Password:)([[:space:]]+)[^ ]+/\1\2********  (saved to .env)/" | grep --line-buffered -vE "INFO|WARNING|GET |WebSocket|connection (open|closed|rejected)|Forbidden"; }'
Enter
Type 'workdir=$(mktemp -d) && cd "$workdir" && clear'
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
