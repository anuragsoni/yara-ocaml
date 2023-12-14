type bigstring = (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

exception Yara_error of int * string

(** Initializes the yara library. This function needs to be called before using any other yara functionality. *)
external initialize : unit -> unit = "yara_stubs_initialize"

(** Releases any resources allocated by the yara library. *)
external finalize : unit -> unit = "yara_stubs_finalize"

module Rule : sig
  type t =
    { identifier : string
    ; tags : string list
    ; namespace : string option
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
  val get_rules_matching : t -> ?pos:int -> ?len:int -> bigstring -> Rule.t list
end
