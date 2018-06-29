open OUnit2

let suite = "x86 suite" >::: [
  "should assemble single ret instruction" >:: (fun ctx ->
    let buf = Iobuf.create 1 in

    X86.ret buf ;

    assert_equal ctx (Iobuf.to_string buf) "\xc3"
  );
];;

let () = run_test_tt_main suite ;;
