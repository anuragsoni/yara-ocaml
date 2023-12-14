type bigstring = (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

exception Yara_error of int * string

let () = Callback.register_exception "yara exception" (Yara_error (-1, "<function name>"))

external initialize : unit -> unit = "yara_stubs_initialize"
external finalize : unit -> unit = "yara_stubs_finalize"

module Rule = struct
  module Yara_string = struct
    type t =
      { identifier : string
      ; fixed_offset : int64 option
      ; length : int
      ; rule_index : int
      }
  end

  type t =
    { identifier : string
    ; tags : string list
    ; namespace : string option
    ; strings : Yara_string.t list
    }
end

module Rules = struct
  type t
end

module Compiler = struct
  type t

  module Error = struct
    type t =
      { level : string
      ; line_number : int
      }
  end

  exception Yara_compiler_error of Error.t list

  let () = Callback.register_exception "yara compiler error" (Yara_compiler_error [])

  external create : unit -> t = "yara_stubs_create_compiler"

  external add_string
    :  ?namespace:string
    -> t
    -> string
    -> unit
    = "yara_stubs_compiler_add_string"

  external get_rules : t -> Rules.t = "yara_stubs_get_rules"
end

module Scanner = struct
  type t

  external create : Rules.t -> t = "yara_stubs_scanner_create"
  external set_timeout : t -> int -> unit = "yara_stubs_set_scanner_timeout"

  external get_rules_matching
    :  t
    -> bigstring
    -> pos:int
    -> len:int
    -> Rule.t list
    = "yara_stubs_scanner_get_rules_matching"

  let get_rules_matching t ?(pos = 0) ?len buf =
    let total_length = Bigarray.Array1.dim buf in
    let len =
      match len with
      | None -> total_length - pos
      | Some i -> i
    in
    if pos < 0
    then invalid_arg (Printf.sprintf "get_rules_matching: Negative position %d" pos);
    if len < 0
    then invalid_arg (Printf.sprintf "get_rules_matching: Negative length %d" len);
    if pos > total_length - len
    then
      invalid_arg
        (Printf.sprintf
           "get_rules_matching: pos + len > total_length: %d + %d > %d"
           pos
           len
           total_length);
    get_rules_matching t buf ~pos ~len
  ;;
end
