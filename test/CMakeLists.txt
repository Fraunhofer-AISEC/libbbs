set(BBS_FIX_TESTS
    bbs_fix_msg_scalars.c
    bbs_fix_generators.c
    bbs_fix_keygen.c
    bbs_fix_sign.c
    bbs_fix_verify.c
    bbs_fix_proof_gen.c
    bbs_fix_proof_verify.c
    bbs_fix_hash_to_scalar.c
    bbs_fix_expand_message.c)

set(BBS_E2E_TESTS bbs_e2e_sign_n_proof.c)
set(BBS_BENCH_TESTS bbs_bench_e2e.c bbs_bench_individual.c)

create_test_sourcelist(fixture-tests bbs-test-fixtures.c ${BBS_FIX_TESTS})
create_test_sourcelist(e2e-tests bbs-test-e2e.c ${BBS_E2E_TESTS})
create_test_sourcelist(bench-tests bbs-test-bench.c ${BBS_BENCH_TESTS})

add_executable(bbs-test-fixtures ${fixture-tests} fixtures.c)
target_link_libraries(bbs-test-fixtures PRIVATE bbs)

add_executable(bbs-test-e2e ${e2e-tests})
target_link_libraries(bbs-test-e2e PRIVATE bbs)

add_executable(bbs-test-bench ${bench-tests})
target_link_libraries(bbs-test-bench PRIVATE bbs)
target_compile_definitions(bbs-test-bench PUBLIC ENABLE_BENCHMARK)
add_custom_target(bench COMMAND bbs-test-bench)

foreach(test ${BBS_FIX_TESTS})
  get_filename_component(TName ${test} NAME_WE)
  add_test(NAME ${TName} COMMAND bbs-test-fixtures ${TName})
endforeach()

foreach(test ${BBS_E2E_TESTS})
  get_filename_component(TName ${test} NAME_WE)
  add_test(NAME ${TName} COMMAND bbs-test-e2e ${TName})
endforeach()

foreach(test ${BBS_BENCH_TESTS})
  get_filename_component(TName ${test} NAME_WE)
  add_test(NAME ${TName} COMMAND bbs-test-bench ${TName})
endforeach()
