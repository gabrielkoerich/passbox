on run argv
    set q to item 1 of argv
    set output to ""
    tell application "Mail"
        set hits to (messages of inbox whose subject contains q)
        set lim to 20
        set total to (count of hits)
        if lim > total then set lim to total
        repeat with i from 1 to lim
            set m to item i of hits
            set output to output & (date received of m as string) & " | " & (sender of m) & " | " & (subject of m) & linefeed
        end repeat
    end tell
    return output
end run
