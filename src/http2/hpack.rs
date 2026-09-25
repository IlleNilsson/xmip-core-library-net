//! HPACK, RFC 7541: the header compression HTTP/2 writes every header
//! block in. The integer and string representations ([`integer`],
//! [`literal`]), the Huffman code of Appendix B ([`huffman`] over
//! [`code`]), the static and dynamic table ([`table`]), and both sides:
//! an [`Encoder`] and a [`Decoder`], each keeping its table in step with
//! the peer's.

pub mod code;
mod decoder;
mod encoder;
pub mod huffman;
pub mod integer;
pub mod literal;
pub mod table;

pub use decoder::Decoder;
pub use encoder::Encoder;

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
        digits
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex")
            })
            .collect()
    }

    fn list(fields: &[(&str, &str)]) -> Vec<(String, String)> {
        fields
            .iter()
            .map(|&(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    /// One block of Appendix C: the list, the block as printed, and the
    /// dynamic table after it — its names newest first, and its size.
    struct Example<'a> {
        section: &'a str,
        fields: &'a [(&'a str, &'a str)],
        block: &'a str,
        names: &'a [&'a str],
        size: usize,
    }

    /// Decode and encode each block in turn on one connection, as the
    /// section does, and hold the tables to what it prints.
    fn run(examples: &[Example<'_>], table_size: usize, huffman: bool) {
        let mut decoder = Decoder::new(table_size);
        let mut encoder = Encoder::new(table_size, huffman);
        for example in examples {
            let block = hex(example.block);
            let read = decoder.decode(&block).expect(example.section);
            assert_eq!(read, list(example.fields), "{}", example.section);
            let written = encoder.encode(example.fields.iter().copied());
            assert_eq!(written, block, "{}", example.section);
            for table in [decoder.table(), encoder.table()] {
                let names: Vec<&str> = table.dynamic().map(|(name, _)| name.as_str()).collect();
                assert_eq!(names, example.names, "{}", example.section);
                assert_eq!(table.size(), example.size, "{}", example.section);
            }
        }
    }

    const REQUEST_1: &[(&str, &str)] = &[
        (":method", "GET"),
        (":scheme", "http"),
        (":path", "/"),
        (":authority", "www.example.com"),
    ];
    const REQUEST_2: &[(&str, &str)] = &[
        (":method", "GET"),
        (":scheme", "http"),
        (":path", "/"),
        (":authority", "www.example.com"),
        ("cache-control", "no-cache"),
    ];
    const REQUEST_3: &[(&str, &str)] = &[
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/index.html"),
        (":authority", "www.example.com"),
        ("custom-key", "custom-value"),
    ];
    const RESPONSE_1: &[(&str, &str)] = &[
        (":status", "302"),
        ("cache-control", "private"),
        ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
        ("location", "https://www.example.com"),
    ];
    const RESPONSE_2: &[(&str, &str)] = &[
        (":status", "307"),
        ("cache-control", "private"),
        ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
        ("location", "https://www.example.com"),
    ];
    const RESPONSE_3: &[(&str, &str)] = &[
        (":status", "200"),
        ("cache-control", "private"),
        ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
        ("location", "https://www.example.com"),
        ("content-encoding", "gzip"),
        (
            "set-cookie",
            "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
        ),
    ];
    const AFTER_REQUEST_1: &[&str] = &[":authority"];
    const AFTER_REQUEST_2: &[&str] = &["cache-control", ":authority"];
    const AFTER_REQUEST_3: &[&str] = &["custom-key", "cache-control", ":authority"];
    const AFTER_RESPONSE_1: &[&str] = &["location", "date", "cache-control", ":status"];
    const AFTER_RESPONSE_2: &[&str] = &[":status", "location", "date", "cache-control"];
    const AFTER_RESPONSE_3: &[&str] = &["set-cookie", "content-encoding", "date"];

    #[test]
    fn appendix_c_2_each_representation_on_its_own() {
        let independent = [
            (
                "400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572",
                ("custom-key", "custom-header"),
                55,
            ),
            (
                "040c 2f73 616d 706c 652f 7061 7468",
                (":path", "/sample/path"),
                0,
            ),
            (
                "1008 7061 7373 776f 7264 0673 6563 7265 74",
                ("password", "secret"),
                0,
            ),
            ("82", (":method", "GET"), 0),
        ];
        for (block, field, size) in independent {
            let mut decoder = Decoder::new(4096);
            assert_eq!(decoder.decode(&hex(block)).expect(block), list(&[field]));
            assert_eq!(decoder.table().size(), size, "{block}");
        }
        let mut encoder = Encoder::new(4096, false);
        assert_eq!(
            encoder.encode([("custom-key", "custom-header")]),
            hex(independent[0].0)
        );
        assert_eq!(encoder.encode([(":method", "GET")]), [0x82]);
    }

    #[test]
    fn appendix_c_3_requests_without_huffman_coding() {
        run(
            &[
                Example {
                    section: "C.3.1",
                    fields: REQUEST_1,
                    block: "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
                    names: AFTER_REQUEST_1,
                    size: 57,
                },
                Example {
                    section: "C.3.2",
                    fields: REQUEST_2,
                    block: "8286 84be 5808 6e6f 2d63 6163 6865",
                    names: AFTER_REQUEST_2,
                    size: 110,
                },
                Example {
                    section: "C.3.3",
                    fields: REQUEST_3,
                    block: "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d \
                            7661 6c75 65",
                    names: AFTER_REQUEST_3,
                    size: 164,
                },
            ],
            4096,
            false,
        );
    }

    #[test]
    fn appendix_c_4_requests_with_huffman_coding() {
        run(
            &[
                Example {
                    section: "C.4.1",
                    fields: REQUEST_1,
                    block: "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
                    names: AFTER_REQUEST_1,
                    size: 57,
                },
                Example {
                    section: "C.4.2",
                    fields: REQUEST_2,
                    block: "8286 84be 5886 a8eb 1064 9cbf",
                    names: AFTER_REQUEST_2,
                    size: 110,
                },
                Example {
                    section: "C.4.3",
                    fields: REQUEST_3,
                    block: "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
                    names: AFTER_REQUEST_3,
                    size: 164,
                },
            ],
            4096,
            true,
        );
    }

    #[test]
    fn appendix_c_5_responses_without_huffman_coding_evicting_at_256() {
        run(
            &[
                Example {
                    section: "C.5.1",
                    fields: RESPONSE_1,
                    block: "4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 \
                            7420 3230 3133 2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 \
                            3a2f 2f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
                    names: AFTER_RESPONSE_1,
                    size: 222,
                },
                Example {
                    section: "C.5.2",
                    fields: RESPONSE_2,
                    block: "4803 3330 37c1 c0bf",
                    names: AFTER_RESPONSE_2,
                    size: 222,
                },
                Example {
                    section: "C.5.3",
                    fields: RESPONSE_3,
                    block: "88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 \
                            3a32 3220 474d 54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 \
                            514b 425a 584f 5157 454f 5049 5541 5851 5745 4f49 553b 206d 6178 \
                            2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e 3d31",
                    names: AFTER_RESPONSE_3,
                    size: 215,
                },
            ],
            256,
            false,
        );
    }

    #[test]
    fn appendix_c_6_responses_with_huffman_coding_evicting_at_256() {
        run(
            &[
                Example {
                    section: "C.6.1",
                    fields: RESPONSE_1,
                    block: "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 \
                            0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae \
                            43d3",
                    names: AFTER_RESPONSE_1,
                    size: 222,
                },
                Example {
                    section: "C.6.2",
                    fields: RESPONSE_2,
                    block: "4883 640e ffc1 c0bf",
                    names: AFTER_RESPONSE_2,
                    size: 222,
                },
                Example {
                    section: "C.6.3",
                    fields: RESPONSE_3,
                    block: "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff \
                            c05a 839b d9ab 77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af \
                            2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 \
                            07",
                    names: AFTER_RESPONSE_3,
                    size: 215,
                },
            ],
            256,
            true,
        );
    }
}
