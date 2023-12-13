# Yara-ocaml

OCaml bindings to [libyara](https://yara.readthedocs.io/en/stable/capi.html). This library allows you to integrate [yara](https://yara.readthedocs.io/en/stable/index.html) into your OCaml projects by leveraging yara's C api.

The library is very much a work-in-progress and there are quite a few gaps in the API coverage.

## Installing

Build and install [yara](https://yara.readthedocs.io/en/stable/index.html) on the host operating system, and ensure that the yara library can be discovered
using [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/). The current implementation is tested against yara 4.3.x releases.

## Initializing and finalizing libyara

The OCaml bindings follow a similar pattern as yara's C api and require manual initialization and finalizing the yara library. Call `Yara.initialize ()` once before using any other function from the Yara module. `Yara.finalize ()` must be called after finishing using the yara library.

## Example

```ocaml
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
  Yara.initialize ();
  Fun.protect ~finally:(fun () -> Yara.finalize ()) (fun () -> main ())
;;
```
