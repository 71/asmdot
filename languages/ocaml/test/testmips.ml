open OUnit2

let suite = "mips suite" >::: [
  "should assemble single addi instruction" >:: (fun ctx ->
    let buf = Iobuf.create 4 in

    Mips.addi buf Reg.t1 Reg.t2 0;

    assert_equal ctx (Iobuf.to_string buf) "\x00\x00\x49\x21"
  );
];;

let () = run_test_tt_main suite ;;
