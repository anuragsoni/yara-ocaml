type bigstring = (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

exception Yara_error of int * string

(** Initializes the yara library. This function needs to be called before using any other yara functionality. *)
external initialize : unit -> unit = "yara_stubs_initialize"

(** Releases any resources allocated by the yara library. *)
external finalize : unit -> unit = "yara_stubs_finalize"

module Rule : sig
  module Yara_string : sig
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

module Rules : sig
  type t
end

module Compiler : sig
  type t

  module Error : sig
    type t =
      { level : string
      ; line_number : int
      }
  end

  exception Yara_compiler_error of Error.t list

  val create : unit -> t
  val add_string : ?namespace:string -> t -> string -> unit
  val get_rules : t -> Rules.t
end

module Scanner : sig
  type t

  val create : Rules.t -> t
  val set_timeout : t -> int -> unit
  val set_integer_variable : t -> string -> int64 -> unit
  val set_float_variable : t -> string -> float -> unit
  val set_string_variable : t -> string -> string -> unit
  val set_boolean_variable : t -> string -> bool -> unit
  val get_rules_matching : t -> ?pos:int -> ?len:int -> bigstring -> Rule.t list
end
