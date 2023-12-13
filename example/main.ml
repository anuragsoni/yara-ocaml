let create_rules () =
  let compiler = Yara.Compiler.create () in
  Yara.Compiler.add_string compiler {|rule foo: bar {strings: $a = "lmn" condition: $a}|};
  Yara.Compiler.get_rules compiler
;;

let main () =
  let scanner = Yara.Scanner.create (create_rules ()) in
  let payload = Bytes.of_string "abcdefgjiklmnoprstuvwxyz" in
  match Yara.Scanner.get_rules_matching scanner payload with
  | [] -> print_endline "No rules matched"
  | xs ->
    List.iter (fun (rule : Yara.Rule.t) -> Printf.printf "Rule: %s\n" rule.identifier) xs
;;

let () =
  Printexc.record_backtrace true;
  Yara.initialize ();
  Fun.protect ~finally:(fun () -> Yara.finalize ()) (fun () -> main ())
;;
