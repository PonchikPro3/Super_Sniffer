# tests/test_sniffer_core.py

import unittest
from sniffer_core import get_ip_from_url, parse_filters, should_display_line


class TestGetIPFromURL(unittest.TestCase):

    def test_valid_http_url(self):
        self.assertEqual(get_ip_from_url("http://example.com"), "23.220.75.232")

    def test_url_with_path(self):
        self.assertEqual(get_ip_from_url("http://example.com/path?query=1"), "23.220.75.232")

    def test_url_with_port(self):
        self.assertEqual(get_ip_from_url("http://example.com:8080"), "23.220.75.232")

    def test_invalid_url_no_host(self):
        with self.assertRaises(ValueError):
            get_ip_from_url("http://")

    def test_empty_url(self):
        with self.assertRaises(ValueError):
            get_ip_from_url("")

    def test_non_string_input(self):
        with self.assertRaises(ValueError):
            get_ip_from_url(None)


class TestParseFilters(unittest.TestCase):

    def test_empty_string(self):
        self.assertEqual(parse_filters(""), [])
        self.assertEqual(parse_filters("   "), [])

    def test_single_keyword(self):
        self.assertEqual(parse_filters("HTTP"), ["HTTP"])

    def test_multiple_keywords(self):
        self.assertEqual(parse_filters("HTTP\n200\nGET"), ["HTTP", "200", "GET"])

    def test_with_whitespace(self):
        self.assertEqual(parse_filters("  HTTP  \n  200  "), ["HTTP", "200"])


class TestShouldDisplayLine(unittest.TestCase):

    def test_no_filters_always_true(self):
        self.assertTrue(should_display_line("test line", [], False, False))
        self.assertTrue(should_display_line("test line", ["HTTP"], False, False))

    def test_use_filters_match(self):
        self.assertTrue(should_display_line("GET / HTTP/1.1", ["HTTP"], True, False))

    def test_use_filters_no_match(self):
        self.assertFalse(should_display_line("POST /api", ["HTTP"], True, False))

    def test_invert_filters_no_match(self):
        self.assertTrue(should_display_line("POST /api", ["HTTP"], True, True))

    def test_invert_filters_match(self):
        self.assertFalse(should_display_line("GET / HTTP/1.1", ["HTTP"], True, True))


if __name__ == "__main__":
    unittest.main()