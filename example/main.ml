open Core

module Yara_string = struct
  type t = Yara.Rule.Yara_string.t =
    { identifier : string
    ; fixed_offset : int64 option
    ; length : int
    ; rule_index : int
    }
  [@@deriving sexp_of]
end

module Yara_rule = struct
  type t = Yara.Rule.t =
    { identifier : string
    ; tags : string list
    ; namespace : string option
    ; strings : Yara_string.t list
    }
  [@@deriving sexp_of]
end

let create_rules () =
  let compiler = Yara.Compiler.create () in
  Yara.Compiler.add_string compiler {|rule foo: bar {strings: $a = "lmn" condition: $a}|};
  Yara.Compiler.get_rules compiler
;;

let main () =
  let scanner = Yara.Scanner.create (create_rules ()) in
  let payload = Bigstring.of_string "abcdefgjiklmnoprstuvwxyz" in
  match Yara.Scanner.get_rules_matching scanner payload with
  | [] -> print_endline "No rules matched"
  | xs ->
    List.iter
      ~f:(fun (rule : Yara.Rule.t) -> printf !"Rule: %{sexp: Yara_rule.t}\n" rule)
      xs
;;

let () =
  Printexc.record_backtrace true;
  Yara.initialize ();
  Fun.protect ~finally:(fun () -> Yara.finalize ()) (fun () -> main ())
;;
