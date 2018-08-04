open OUnit2

let suite = "arm suite" >::: [
  "should encode single cps instruction" >:: (fun ctx ->
    let buf = Iobuf.create 4 in

    Arm.cps buf Mode.USR ;

    assert_equal ctx (Iobuf.to_string buf) "\x10\x00\x02\xf1"
  );
];;

let () = run_test_tt_main suite ;;
