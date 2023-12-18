(lang dune 3.1)

(name yara)

(generate_opam_files true)

(maintainers "Anurag Soni <anurag@sonianurag.com>")

(authors "Anurag Soni <anurag@sonianurag.com>")

(license "MPL-2.0")

(source
 (sourcehut soni/yara-ocaml))

(package
 (name yara)
 (synopsis "OCaml bindings for libyara")
 (depends
  conf-c++
  dune-configurator
  (ocaml
   (>= 4.13.0))))
