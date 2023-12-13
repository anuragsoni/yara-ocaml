module C = Configurator.V1

let () =
  C.main ~name:"ocaml-yara" (fun c ->
    let default : C.Pkg_config.package_conf = { libs = [ "-lyara" ]; cflags = [] } in
    let conf =
      match C.Pkg_config.get c with
      | None -> default
      | Some pc ->
        (match C.Pkg_config.query pc ~package:"yara" with
         | None -> default
         | Some deps -> deps)
    in
    let callback_constants =
      [ "CALLBACK_MSG_RULE_MATCHING"
      ; "CALLBACK_MSG_RULE_NOT_MATCHING"
      ; "CALLBACK_MSG_SCAN_FINISHED"
      ; "CALLBACK_MSG_IMPORT_MODULE"
      ; "CALLBACK_MSG_MODULE_IMPORTED"
      ; "CALLBACK_MSG_TOO_MANY_MATCHES"
      ; "CALLBACK_MSG_CONSOLE_LOG"
      ; "CALLBACK_CONTINUE"
      ; "CALLBACK_ABORT"
      ; "CALLBACK_ERROR"
      ]
    in
    let error_constants =
      [ "ERROR_SUCCESS"
      ; "ERROR_INSUFFICIENT_MEMORY"
      ; "ERROR_COULD_NOT_ATTACH_TO_PROCESS"
      ; "ERROR_COULD_NOT_OPEN_FILE"
      ; "ERROR_COULD_NOT_MAP_FILE"
      ; "ERROR_INVALID_FILE"
      ; "ERROR_CORRUPT_FILE"
      ; "ERROR_UNSUPPORTED_FILE_VERSION"
      ; "ERROR_INVALID_REGULAR_EXPRESSION"
      ; "ERROR_INVALID_HEX_STRING"
      ; "ERROR_SYNTAX_ERROR"
      ; "ERROR_LOOP_NESTING_LIMIT_EXCEEDED"
      ; "ERROR_DUPLICATED_LOOP_IDENTIFIER"
      ; "ERROR_DUPLICATED_IDENTIFIER"
      ; "ERROR_DUPLICATED_TAG_IDENTIFIER"
      ; "ERROR_DUPLICATED_META_IDENTIFIER"
      ; "ERROR_DUPLICATED_STRING_IDENTIFIER"
      ; "ERROR_UNREFERENCED_STRING"
      ; "ERROR_UNDEFINED_STRING"
      ; "ERROR_UNDEFINED_IDENTIFIER"
      ; "ERROR_MISPLACED_ANONYMOUS_STRING"
      ; "ERROR_INCLUDES_CIRCULAR_REFERENCE"
      ; "ERROR_INCLUDE_DEPTH_EXCEEDED"
      ; "ERROR_WRONG_TYPE"
      ; "ERROR_EXEC_STACK_OVERFLOW"
      ; "ERROR_SCAN_TIMEOUT"
      ; "ERROR_TOO_MANY_SCAN_THREADS"
      ; "ERROR_CALLBACK_ERROR"
      ; "ERROR_INVALID_ARGUMENT"
      ; "ERROR_TOO_MANY_MATCHES"
      ; "ERROR_INTERNAL_FATAL_ERROR"
      ; "ERROR_NESTED_FOR_OF_LOOP"
      ; "ERROR_INVALID_FIELD_NAME"
      ; "ERROR_UNKNOWN_MODULE"
      ; "ERROR_NOT_A_STRUCTURE"
      ; "ERROR_NOT_INDEXABLE"
      ; "ERROR_NOT_A_FUNCTION"
      ; "ERROR_INVALID_FORMAT"
      ; "ERROR_TOO_MANY_ARGUMENTS"
      ; "ERROR_WRONG_ARGUMENTS"
      ; "ERROR_WRONG_RETURN_TYPE"
      ; "ERROR_DUPLICATED_STRUCTURE_MEMBER"
      ; "ERROR_EMPTY_STRING"
      ; "ERROR_DIVISION_BY_ZERO"
      ; "ERROR_REGULAR_EXPRESSION_TOO_LARGE"
      ; "ERROR_TOO_MANY_RE_FIBERS"
      ; "ERROR_COULD_NOT_READ_PROCESS_MEMORY"
      ; "ERROR_INVALID_EXTERNAL_VARIABLE_TYPE"
      ; "ERROR_REGULAR_EXPRESSION_TOO_COMPLEX"
      ; "ERROR_INVALID_MODULE_NAME"
      ; "ERROR_TOO_MANY_STRINGS"
      ; "ERROR_INTEGER_OVERFLOW"
      ; "ERROR_CALLBACK_REQUIRED"
      ; "ERROR_INVALID_OPERAND"
      ; "ERROR_COULD_NOT_READ_FILE"
      ; "ERROR_DUPLICATED_EXTERNAL_VARIABLE"
      ; "ERROR_INVALID_MODULE_DATA"
      ; "ERROR_WRITING_FILE"
      ; "ERROR_INVALID_MODIFIER"
      ; "ERROR_DUPLICATED_MODIFIER"
      ; "ERROR_BLOCK_NOT_READY"
      ; "ERROR_INVALID_PERCENTAGE"
      ; "ERROR_IDENTIFIER_MATCHES_WILDCARD"
      ; "ERROR_INVALID_VALUE"
      ]
    in
    let int_constants =
      C.C_define.import
        c
        ~c_flags:conf.cflags
        ~includes:[ "yara/rules.h"; "yara/error.h" ]
        (List.map
           (fun name -> name, C.C_define.Type.Int)
           (List.concat [ error_constants; callback_constants ]))
    in
    let error_constants =
      List.filter
        (fun (name, _) -> String.starts_with ~prefix:"ERROR_" name)
        int_constants
    in
    let callback_constants =
      List.filter
        (fun (name, _) -> String.starts_with ~prefix:"CALLBACK_" name)
        int_constants
    in
    print_endline "module Yara_error = struct";
    List.iter
      (fun (name, value) ->
        match value with
        | C.C_define.Value.Int d ->
          Printf.printf "let %s = %d\n\n" (String.lowercase_ascii name) d
        | _ -> assert false)
      error_constants;
    print_endline "end";
    print_endline "module Yara_callback = struct";
    List.iter
      (fun (name, value) ->
        match value with
        | C.C_define.Value.Int d ->
          Printf.printf "let %s = %d\n\n" (String.lowercase_ascii name) d
        | _ -> assert false)
      callback_constants;
    print_endline "end")
;;
