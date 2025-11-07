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
create_test_sourcelist(experimental bbs-test-experimental.c
	bbs_experimental_compressed_proofs.c
	bbs_experimental_compressed_proofs_250.c)

add_executable(bbs-test-fixtures-suite-bls12-381-shake-256 ${fixture-tests} fixtures.c)
target_compile_definitions(bbs-test-fixtures-suite-bls12-381-shake-256 PUBLIC LIBBBS_TEST_SUITE_SHAKE256)
add_executable(bbs-test-fixtures-suite-bls12-381-sha-256 ${fixture-tests} fixtures.c)
target_compile_definitions(bbs-test-fixtures-suite-bls12-381-sha-256 PUBLIC LIBBBS_TEST_SUITE_SHA256)
target_link_libraries(bbs-test-fixtures-suite-bls12-381-sha-256 PRIVATE
	bbs_FIXTURES_ONLY)
target_link_libraries(bbs-test-fixtures-suite-bls12-381-shake-256 PRIVATE
	bbs_FIXTURES_ONLY)
target_include_directories(bbs-test-fixtures-suite-bls12-381-sha-256 PUBLIC
	../include ../src ${BINARY_DIR}/include)
target_include_directories(bbs-test-fixtures-suite-bls12-381-shake-256 PUBLIC
	../include ../src ${BINARY_DIR}/include)

add_executable(bbs-test-e2e-suite-bls12-381-sha-256 ${e2e-tests})
target_compile_definitions(bbs-test-e2e-suite-bls12-381-sha-256 PUBLIC LIBBBS_TEST_SUITE_SHAKE256)
add_executable(bbs-test-e2e-suite-bls12-381-shake-256 ${e2e-tests})
target_compile_definitions(bbs-test-e2e-suite-bls12-381-shake-256 PUBLIC LIBBBS_TEST_SUITE_SHAKE256)
target_link_libraries(bbs-test-e2e-suite-bls12-381-sha-256 PRIVATE bbs)
target_link_libraries(bbs-test-e2e-suite-bls12-381-shake-256 PRIVATE bbs)
target_include_directories(bbs-test-e2e-suite-bls12-381-sha-256 PUBLIC ../include)
target_include_directories(bbs-test-e2e-suite-bls12-381-shake-256 PUBLIC ../include)

add_executable(bbs-test-bench-suite-bls12-381-sha-256 ${bench-tests})
target_link_libraries(bbs-test-bench-suite-bls12-381-sha-256 PRIVATE bbs)
target_compile_definitions(bbs-test-bench-suite-bls12-381-sha-256 PUBLIC ENABLE_BENCHMARK)
target_compile_definitions(bbs-test-bench-suite-bls12-381-sha-256 PUBLIC LIBBBS_TEST_SUITE_SHA256)
add_executable(bbs-test-bench-suite-bls12-381-shake-256 ${bench-tests})
target_link_libraries(bbs-test-bench-suite-bls12-381-shake-256 PRIVATE bbs)
target_compile_definitions(bbs-test-bench-suite-bls12-381-shake-256 PUBLIC ENABLE_BENCHMARK)
target_compile_definitions(bbs-test-bench-suite-bls12-381-shake-256 PUBLIC LIBBBS_TEST_SUITE_SHAKE256)
target_include_directories(bbs-test-bench-suite-bls12-381-sha-256 PUBLIC ../include)
target_include_directories(bbs-test-bench-suite-bls12-381-shake-256 PUBLIC ../include)
# Do not automatically bench the e2e test as it has too many iterations
add_custom_target(bench COMMAND bbs-test-bench-suite-bls12-381-shake-256 bbs_bench_individual  COMMAND bbs-test-bench-suite-bls12-381-sha-256 bbs_bench_individual)

add_executable(bbs-test-experimental-sha-256 ${experimental} fixtures.c)
target_compile_definitions(bbs-test-experimental-sha-256 PUBLIC LIBBBS_TEST_SUITE_SHA256)
add_executable(bbs-test-experimental-shake-256 ${experimental} fixtures.c)
target_compile_definitions(bbs-test-experimental-shake-256 PUBLIC LIBBBS_TEST_SUITE_SHAKE256)
target_link_libraries(bbs-test-experimental-sha-256 PRIVATE bbs_FIXTURES_ONLY)
target_link_libraries(bbs-test-experimental-shake-256 PRIVATE bbs_FIXTURES_ONLY)
target_include_directories(bbs-test-experimental-sha-256 PUBLIC ../include
	../src)
target_include_directories(bbs-test-experimental-shake-256 PUBLIC ../include
	../src)

foreach(test ${BBS_FIX_TESTS})
  get_filename_component(TName ${test} NAME_WE)
  add_test(NAME ${TName}-suite-bls12-381-shake-256 COMMAND bbs-test-fixtures-suite-bls12-381-shake-256 ${TName})
endforeach()
foreach(test ${BBS_FIX_TESTS})
  get_filename_component(TName ${test} NAME_WE)
  add_test(NAME ${TName}-suite-bls12-381-sha-256 COMMAND bbs-test-fixtures-suite-bls12-381-sha-256 ${TName})
endforeach()
add_test(NAME experimental-compressed-proofs-shake-256 COMMAND
	bbs-test-experimental-shake-256 bbs_experimental_compressed_proofs)
add_test(NAME experimental-compressed-proofs-sha-256   COMMAND
	bbs-test-experimental-sha-256 bbs_experimental_compressed_proofs)
add_test(NAME experimental-compressed-proofs-250-shake-256 COMMAND
	bbs-test-experimental-shake-256 bbs_experimental_compressed_proofs_250)
add_test(NAME experimental-compressed-proofs-250-sha-256   COMMAND
	bbs-test-experimental-sha-256 bbs_experimental_compressed_proofs_250)


foreach(test ${BBS_E2E_TESTS})
  get_filename_component(TName ${test} NAME_WE)
  add_test(NAME ${TName}-suite-bls12-381-shake-256 COMMAND bbs-test-e2e-suite-bls12-381-shake-256 ${TName})
endforeach()

foreach(test ${BBS_E2E_TESTS})
  get_filename_component(TName ${test} NAME_WE)
  add_test(NAME ${TName}-suite-bls12-381-sha-256 COMMAND bbs-test-e2e-suite-bls12-381-sha-256 ${TName})
endforeach()

