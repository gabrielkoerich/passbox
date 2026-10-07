on run argv
    set lim to 10
    if (count of argv) > 0 and item 1 of argv is not "" then set lim to (item 1 of argv) as integer
    set output to ""
    tell application "Mail"
        set msgs to messages of inbox
        set total to (count of msgs)
        if lim > total then set lim to total
        repeat with i from 1 to lim
            set m to item i of msgs
            set output to output & (date received of m as string) & " | " & (sender of m) & " | " & (subject of m) & linefeed
        end repeat
    end tell
    return output
end run
