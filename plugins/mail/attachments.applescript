on run argv
    set q to item 1 of argv
    set destDir to ""
    if (count of argv) > 1 and item 2 of argv is not "" then set destDir to item 2 of argv
    if destDir is "" then set destDir to (POSIX path of (path to downloads folder))
    if destDir does not end with "/" then set destDir to destDir & "/"
    set saved to ""
    set seen to 0
    tell application "Mail"
        set hits to (messages of inbox whose subject contains q)
        repeat with m in hits
            if seen is greater than or equal to 20 then exit repeat
            set seen to seen + 1
            repeat with a in (mail attachments of m)
                set outPath to destDir & (name of a)
                try
                    save a in (POSIX file outPath)
                    set saved to saved & outPath & linefeed
                end try
            end repeat
        end repeat
    end tell
    return saved
end run
