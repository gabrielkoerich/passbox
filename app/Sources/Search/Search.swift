/// The names holding every word of the query, in any order and any case
public func search(_ names: [String], for query: String) -> [String] {
    let words = query.lowercased().split(separator: " ")
    return names.filter { name in words.allSatisfy { name.lowercased().contains($0) } }
}
