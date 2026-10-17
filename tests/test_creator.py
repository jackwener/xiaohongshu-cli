from xhs_cli.commands.creator import extract_hashtags, format_body_hashtags


def test_extract_hashtags():
    # Normal case
    assert extract_hashtags("This is a #test and another #hashtag") == ["test", "hashtag"]

    # Empty body
    assert extract_hashtags("") == []

    # URL fragment shouldn't match
    assert extract_hashtags("Visit https://example.com#section for more info") == []

    # Consecutive tags without spaces — only the first is preceded by whitespace
    assert extract_hashtags("Mixed #one#two#three") == ["one"]

    # Tags at start of line
    assert extract_hashtags("#start of line") == ["start"]

    # Mix of languages
    assert extract_hashtags("测试 #中文标签 和 #english tag") == ["中文标签", "english"]

    # Trailing hashtag
    assert extract_hashtags("This is #trailing") == ["trailing"]

    # Pure hashtag body
    assert extract_hashtags("#a #b #c") == ["a", "b", "c"]

    # Emoji hashtag
    assert extract_hashtags("Let's go #🎉party") == ["🎉party"]


def test_format_body_hashtags():
    # Empty map returns original
    assert format_body_hashtags("Hello world", {}) == "Hello world"

    # Single replacement
    tag_map = {"美股": "美股"}
    assert format_body_hashtags("分析 #美股 走势", tag_map) == "分析 #美股[话题]# 走势"

    # Multiple replacements with prefix collision prevention (#美股 vs #美股大跌)
    tag_map_multi = {"美股": "美股", "美股大跌": "美股大跌"}
    result = format_body_hashtags("今日盘点 #美股 #美股大跌 发生", tag_map_multi)
    assert result == "今日盘点 #美股[话题]# #美股大跌[话题]# 发生"

    # URL fragment should NOT be formatted
    sample = "Link https://site.com#section here #test"
    mapping = {"section": "section", "test": "test"}
    assert format_body_hashtags(sample, mapping) == "Link https://site.com#section here #test[话题]#"

    # Start of line and end of string
    assert (
        format_body_hashtags("#tag at start and #end", {"tag": "tag", "end": "end"})
        == "#tag[话题]# at start and #end[话题]#"
    )

