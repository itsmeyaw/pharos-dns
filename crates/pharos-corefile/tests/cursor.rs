use pharos_corefile::{Cursor, lex};

#[test]
fn walks_lines_arguments_and_nested_blocks() {
    let tokens = lex(
        "Corefile",
        "first a b\nsecond {\n item x\n nested {\n deep\n }\n}\nempty { }",
    );
    let mut cursor = Cursor::new("Corefile", &tokens);
    assert_eq!(cursor.val(), "");
    assert!(cursor.next_line());
    assert_eq!(cursor.val(), "first");
    assert!(!cursor.next_line());
    assert_eq!(cursor.remaining_args(), ["a", "b"]);
    assert!(cursor.next_line());
    assert_eq!(cursor.val(), "second");
    assert!(cursor.next_block());
    assert_eq!(cursor.val(), "item");
    let mut arg = String::new();
    assert!(cursor.args(&mut [&mut arg]));
    assert_eq!(arg, "x");
    assert!(cursor.next_block());
    assert_eq!(cursor.val(), "nested");
    assert!(cursor.next_block());
    assert_eq!(cursor.val(), "deep");
    assert!(!cursor.next_block());
    assert!(!cursor.next_block());
    assert!(cursor.next());
    assert!(!cursor.next_block());
    assert!(!cursor.next());
    assert_eq!(cursor.val(), "}");
}

#[test]
fn reports_source_location_and_argument_errors() {
    let tokens = lex("imported", "plugin {\n}\nplugin argument");
    let mut cursor = Cursor::new("Corefile", &tokens);
    assert!(cursor.next());
    assert!(cursor.next_arg());
    assert!(cursor.arg_err().message.contains("Unexpected token '{'"));
    assert!(cursor.next());
    assert!(cursor.next());
    assert!(cursor.next_arg());
    let error = cursor.arg_err();
    assert_eq!((error.file.as_str(), error.line), ("imported", 3));
    assert!(error.message.contains("argument"));
}

#[test]
fn caddy_argument_loading_and_line_boundaries() {
    let tokens = lex(
        "Testfile",
        "dir1 arg1 arg2 arg3\ndir2 arg4 arg5\ndir3 arg6 { arg7\ndir4",
    );
    let mut cursor = Cursor::new("Testfile", &tokens);
    let (mut a, mut b, mut c) = (String::new(), String::new(), String::new());
    assert!(cursor.next());
    assert!(cursor.args(&mut [&mut a, &mut b, &mut c]));
    assert_eq!((&*a, &*b, &*c), ("arg1", "arg2", "arg3"));
    assert!(cursor.next());
    assert!(!cursor.args(&mut [&mut a, &mut b, &mut c]));
    assert_eq!((&*a, &*b, &*c), ("arg4", "arg5", "arg3"));
    assert!(cursor.next());
    assert_eq!(cursor.remaining_args(), ["arg6"]);
    assert_eq!(cursor.val(), "arg6");
    assert!(cursor.next());
    assert_eq!(cursor.val(), "{");
    assert!(cursor.next());
    assert!(cursor.next_line());
    assert!(cursor.args(&mut []));
    assert!(!cursor.args(&mut [&mut a]));
}

#[test]
fn caddy_imported_and_multiline_tokens_have_correct_line_boundaries() {
    let mut tokens = lex("one", "first \"two\nlines\" last");
    tokens.extend(lex("two", "imported"));
    let mut cursor = Cursor::new("default", &tokens);
    assert!(cursor.next_arg());
    assert!(cursor.next_arg());
    assert_eq!(cursor.val(), "two\nlines");
    assert!(cursor.next_arg());
    assert!(!cursor.next_arg());
    assert!(cursor.next_line());
    assert_eq!((cursor.file(), cursor.line()), ("two", 1));
    assert!(!cursor.next_line());
    assert_eq!(cursor.val(), "imported");
}

#[test]
fn caddy_next_block_stops_at_eof_and_empty_blocks() {
    let tokens = lex("file", "outer {\n item arg");
    let mut cursor = Cursor::new("file", &tokens);
    assert!(!cursor.next_block());
    assert!(cursor.next());
    assert!(cursor.next_block());
    assert!(cursor.next_block());
    assert!(!cursor.next_block());
    assert!(!cursor.next_block());
    let empty = lex("file", "empty { }");
    let mut cursor = Cursor::new("file", &empty);
    assert!(cursor.next());
    assert!(!cursor.next_block());
    assert_eq!(cursor.val(), "}");
}
