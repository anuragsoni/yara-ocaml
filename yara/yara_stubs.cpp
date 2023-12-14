#include <yara.h>
#include <yara/types.h>

extern "C"
{

#include <caml/alloc.h>
#include <caml/bigarray.h>
#include <caml/callback.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/threads.h>
#include <caml/unixsupport.h>

    void yara_stubs_raise(int error_code, const char *message)
    {
        value args[] = {Val_int(error_code), caml_copy_string(message)};
        caml_raise_with_args(*caml_named_value("yara exception"), 2, args);
    }

    CAMLprim value yara_stubs_initialize(value unit)
    {
        CAMLparam1(unit);
        int result = yr_initialize();
        if (result != ERROR_SUCCESS)
        {
            yara_stubs_raise(result, __FUNCTION__);
        }
        CAMLreturn(Val_unit);
    }

    CAMLprim value yara_stubs_finalize(value unit)
    {
        CAMLparam1(unit);
        int result = yr_finalize();
        if (result != ERROR_SUCCESS)
        {
            yara_stubs_raise(result, __FUNCTION__);
        }
        CAMLreturn(Val_unit);
    }

    // Operations on Yara Compiler

#define Yr_compiler_val(v) (*((YR_COMPILER **)Data_custom_val(v)))

    static struct custom_operations yara_compiler_stub = {
        "yara_stubs_compiler", [](value compiler)
        {
            yr_compiler_destroy(Yr_compiler_val(compiler));
        },
        custom_compare_default, custom_hash_default, custom_serialize_default, custom_deserialize_default, custom_compare_ext_default};

    CAMLprim value yara_stubs_create_compiler(value unit)
    {
        CAMLparam1(unit);
        YR_COMPILER *compiler = NULL;
        int result = yr_compiler_create(&compiler);
        if (result != ERROR_SUCCESS)
        {
            yara_stubs_raise(result, __FUNCTION__);
        }
        CAMLlocal1(v);
        v = caml_alloc_custom_mem(&yara_compiler_stub, sizeof(YR_COMPILER *), sizeof(YR_COMPILER));
        Yr_compiler_val(v) = compiler;
        CAMLreturn(v);
    }

    CAMLprim value yara_stubs_compiler_add_string(value rule_namespace, value compiler, value rule)
    {
        CAMLparam3(rule_namespace, compiler, rule);
        if (Yr_compiler_val(compiler)->errors > 0)
        {
            caml_invalid_argument(
                "Yara compiler can't be used after encountering an error.");
        }
        if (Yr_compiler_val(compiler)->rules != NULL)
        {
            caml_invalid_argument(
                "Yara compiler can't be used after rules have been compiled.");
        }
        CAMLlocal2(errors, cons);
        errors = Val_emptylist;

        auto callback = [&errors, &cons](value j)
        {
            cons = caml_alloc(2, Tag_cons);
            Store_field(cons, 0, j);
            Store_field(cons, 1, errors);
            errors = cons;
        };
        auto thunk = [](int error_level,
                        const char *file_name,
                        int line_number,
                        const YR_RULE *rule,
                        const char *message,
                        void *user_data)
        {
            caml_acquire_runtime_system();

            CAMLparam0();

            CAMLlocal2(error_level_, line_number_);
            error_level_ = error_level == YARA_ERROR_LEVEL_ERROR ? caml_copy_string("error") : caml_copy_string("warning");
            line_number_ = Val_int(line_number);

            CAMLlocal1(v);
            v = caml_alloc(2, 0);
            Store_field(v, 0, error_level_);
            Store_field(v, 1, line_number_);

            (*static_cast<decltype(callback) *>(user_data))(v);
            CAMLdrop;

            caml_release_runtime_system();
        };
        yr_compiler_set_callback(Yr_compiler_val(compiler), thunk, &callback);
        caml_release_runtime_system();
        int error_count = yr_compiler_add_string(Yr_compiler_val(compiler),
                                                 String_val(rule), (rule_namespace == Val_none) ? NULL : String_val(Some_val(rule_namespace)));
        caml_acquire_runtime_system();

        if (error_count > 0)
        {
            caml_raise_with_arg(*caml_named_value("yara compiler error"), errors);
        }
        CAMLreturn(Val_unit);
    }

#define Yr_rules_val(v) (*((YR_RULES **)Data_custom_val(v)))

    static struct custom_operations yara_rules_stub = {
        "yara_stubs_rules", [](value rules)
        {
            yr_rules_destroy(Yr_rules_val(rules));
        },
        custom_compare_default, custom_hash_default, custom_serialize_default, custom_deserialize_default, custom_compare_ext_default};

    CAMLprim value yara_stubs_get_rules(value compiler)
    {
        CAMLparam1(compiler);
        YR_RULES *rules = NULL;
        int result = yr_compiler_get_rules(Yr_compiler_val(compiler), &rules);
        if (result != ERROR_SUCCESS)
        {
            yara_stubs_raise(result, __FUNCTION__);
        }
        CAMLlocal1(v);
        v = caml_alloc_custom_mem(&yara_rules_stub, sizeof(YR_RULES *), sizeof(YR_RULES));
        Yr_rules_val(v) = rules;
        CAMLreturn(v);
    }

#define Yr_scanner_val(v) (*((YR_SCANNER **)Data_custom_val(v)))

    static struct custom_operations yara_scanner_stub = {
        "yara_stubs_scanner", [](value scanner)
        {
            yr_scanner_destroy(Yr_scanner_val(scanner));
        },
        custom_compare_default, custom_hash_default, custom_serialize_default, custom_deserialize_default, custom_compare_ext_default};

    CAMLprim value yara_stubs_scanner_create(value rules)
    {
        CAMLparam1(rules);
        YR_SCANNER *scanner = nullptr;
        int result = yr_scanner_create(Yr_rules_val(rules), &scanner);
        if (result != ERROR_SUCCESS)
        {
            yara_stubs_raise(result, __FUNCTION__);
        }
        CAMLlocal1(v);
        v = caml_alloc_custom_mem(&yara_scanner_stub, sizeof(YR_SCANNER *), sizeof(YR_SCANNER));
        Yr_scanner_val(v) = scanner;
        CAMLreturn(v);
    }

    CAMLprim value yara_stubs_set_scanner_timeout(value scanner, value duration)
    {
        CAMLparam2(scanner, duration);
        yr_scanner_set_timeout(Yr_scanner_val(scanner), Long_val(duration));
        CAMLreturn(Val_unit);
    }

    CAMLprim value yara_stubs_scanner_get_rules_matching(value scanner, value buf, value pos, value len)
    {
        CAMLparam4(scanner, buf, pos, len);
        CAMLlocal2(rules, cons);
        rules = Val_emptylist;

        auto callback = [&rules, &cons](value j)
        {
            cons = caml_alloc(2, Tag_cons);
            Store_field(cons, 0, j);
            Store_field(cons, 1, rules);
            rules = cons;
        };

        auto thunk = [](YR_SCAN_CONTEXT *context,
                        int message,
                        void *message_data,
                        void *user_data) -> int
        {
            caml_acquire_runtime_system();

            CAMLparam0();

            if (message == CALLBACK_MSG_RULE_MATCHING)
            {
                CAMLlocal1(identifier);
                auto rule = static_cast<YR_RULE *>(message_data);
                identifier = caml_copy_string(rule->identifier);

                CAMLlocal2(tags, tags_cons);
                tags = Val_emptylist;
                const char *tag;
                yr_rule_tags_foreach(rule, tag)
                {
                    tags_cons = caml_alloc(2, Tag_cons);
                    Store_field(tags_cons, 0, caml_copy_string(tag));
                    Store_field(tags_cons, 1, tags);
                    tags = tags_cons;
                }

                CAMLlocal1(namespace_);
                if (rule->ns)
                {
                    namespace_ = caml_alloc(1, 0);
                    Store_field(namespace_, 0, caml_copy_string(rule->ns->name));
                }
                else
                {
                    namespace_ = Val_none;
                }

                CAMLlocal2(strings, strings_cons);
                strings = Val_emptylist;
                const YR_STRING *s;
                yr_rule_strings_foreach(rule, s)
                {
                    CAMLlocal1(yr_str);
                    yr_str = caml_alloc(4, 0);
                    Store_field(yr_str, 0, caml_copy_string(s->identifier));

                    if (s->fixed_offset == YR_UNDEFINED)
                    {
                        Store_field(yr_str, 1, Val_none);
                    }
                    else
                    {
                        CAMLlocal1(fixed_offset);
                        fixed_offset = caml_alloc(1, Tag_some);
                        Store_field(fixed_offset, 0, Int64_val(s->fixed_offset));
                        Store_field(yr_str, 1, fixed_offset);
                    }
                    Store_field(yr_str, 2, Val_int(s->length));
                    Store_field(yr_str, 3, Val_int(s->rule_idx));

                    strings_cons = caml_alloc(2, Tag_cons);
                    Store_field(strings_cons, 0, yr_str);
                    Store_field(strings_cons, 1, strings);
                    strings = strings_cons;
                }

                CAMLlocal1(ocaml_rule);
                ocaml_rule = caml_alloc(4, 0);
                Store_field(ocaml_rule, 0, identifier);
                Store_field(ocaml_rule, 1, tags);
                Store_field(ocaml_rule, 2, namespace_);
                Store_field(ocaml_rule, 3, strings);
                (*static_cast<decltype(callback) *>(user_data))(ocaml_rule);
            }

            CAMLdrop;

            caml_release_runtime_system();
            return CALLBACK_CONTINUE;
        };

        yr_scanner_set_callback(Yr_scanner_val(scanner), thunk, &callback);
        yr_scanner_set_flags(Yr_scanner_val(scanner), SCAN_FLAGS_REPORT_RULES_MATCHING);

        caml_release_runtime_system();
        auto *buffer = static_cast<const uint8_t *>(Caml_ba_data_val(buf)) + pos;
        int result = yr_scanner_scan_mem(Yr_scanner_val(scanner), buffer, Unsigned_long_val(len));
        caml_acquire_runtime_system();

        if (result != ERROR_SUCCESS)
        {
            yara_stubs_raise(result, __FUNCTION__);
        }

        CAMLreturn(rules);
    }
}
