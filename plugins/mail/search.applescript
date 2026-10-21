-- Every mailbox of every account, plus the local ones, matching subject or sender, up to 50
on run argv
    set q to item 1 of argv
    set lim to 50
    set found to 0
    set output to ""
    tell application "Mail"
        set boxes to {}
        repeat with a in accounts
            set boxes to boxes & (every mailbox of a)
        end repeat
        set boxes to boxes & (every mailbox)
        repeat with mb in boxes
            if found ≥ lim then exit repeat
            try
                set hits to (messages of mb whose subject contains q or sender contains q)
            on error
                set hits to {}
            end try
            repeat with m in hits
                if found ≥ lim then exit repeat
                set output to output & (date received of m as string) & " | " & (name of mb) & " | " & (sender of m) & " | " & (subject of m) & linefeed
                set found to found + 1
            end repeat
        end repeat
    end tell
    return output
end run
