"""Unit tests for media download helpers."""

from xhs_cli.downloads import download_note_images


class FakeResponse:
    content = b"image-bytes"

    def raise_for_status(self):
        return None


class FakeHttpClient:
    requested_urls = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def get(self, url):
        self.requested_urls.append(url)
        return FakeResponse()


def test_download_note_images_saves_under_note_directory(monkeypatch, tmp_path):
    FakeHttpClient.requested_urls = []
    monkeypatch.setattr("xhs_cli.downloads.httpx.Client", FakeHttpClient)

    data = {
        "items": [
            {
                "id": "note/abc",
                "note_card": {
                    "image_list": [
                        {
                            "url_default": "https://img.example/path/photo.webp!nd_dft_wgth_webp_3",
                        }
                    ]
                },
            }
        ]
    }

    saved = download_note_images(data, tmp_path)

    assert FakeHttpClient.requested_urls == [
        "https://img.example/path/photo.webp!nd_dft_wgth_webp_3",
    ]
    assert len(saved) == 1
    assert saved[0].path == tmp_path / "note-abc" / "image-1.webp"
    assert saved[0].path.read_bytes() == b"image-bytes"
