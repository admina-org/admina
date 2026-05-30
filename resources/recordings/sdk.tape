# GIF — SDK PII redaction (resources/sdk-3lines.gif)
# Run from resources/recordings/ :  vhs sdk.tape
Output "../sdk-3lines.gif"

Set Shell "zsh"
Set FontSize 17
Set Width 1320
Set Height 300
Set Padding 24
Set TypingSpeed 45ms

Hide
Type 'python() { uv run --with ollama python "$@"; }'
Enter
Type 'python demo.py >/dev/null 2>&1 && clear'
Enter
Sleep 12s
Show

Type 'python demo.py'
Sleep 700ms
Enter
Sleep 6s
