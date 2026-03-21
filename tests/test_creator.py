from xhs_cli.commands.creator import extract_hashtags


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
