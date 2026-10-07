on run argv
    set theTo to item 1 of argv
    set theSubject to item 2 of argv
    set theBody to item 3 of argv
    tell application "Mail"
        set msg to make new outgoing message with properties {subject:theSubject, content:theBody, visible:false}
        tell msg to make new to recipient with properties {address:theTo}
        send msg
    end tell
    return "sent to " & theTo
end run
