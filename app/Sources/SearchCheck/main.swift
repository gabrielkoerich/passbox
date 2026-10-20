// The Command Line Tools ship no XCTest and SwiftPM does not find their Testing, so a plain run checks it
import Search

let names = ["github/token", "GitHub/Deploy-Key", "db/password", "aws/prod/key"]

func expect(_ query: String, _ want: [String], in list: [String] = names) {
    let got = search(list, for: query)
    precondition(got == want, "search for \"\(query)\" gave \(got), want \(want)")
}

expect("", names)
expect("   ", names)
expect("prod key", ["aws/prod/key"])
expect("key prod", ["aws/prod/key"])
expect("  key   aws ", ["aws/prod/key"])
expect("GITHUB", ["github/token", "GitHub/Deploy-Key"])
expect("deploy-key", ["GitHub/Deploy-Key"])
expect("stripe", [])
expect("github stripe", [])
expect("github", [], in: [])
print("search: every case passed")
