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
