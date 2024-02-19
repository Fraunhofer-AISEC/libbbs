create_test_sourcelist(fixture-tests
	bbs-test-fixtures.c
	bbs_fix_msg_scalars.c
	bbs_fix_generators.c
	bbs_fix_keygen.c
	bbs_fix_sign.c
	bbs_fix_verify.c
	bbs_fix_proof_gen.c
	bbs_fix_proof_verify.c
	)

create_test_sourcelist(e2e-tests
	bbs-test-e2e.c
	bbs_e2e_sign_n_proof.c
	)

add_executable(bbs-test-fixtures ${fixture-tests} fixtures.c)
target_link_libraries(bbs-test-fixtures PRIVATE bbs)

add_executable(bbs-test-e2e ${e2e-tests})
target_link_libraries(bbs-test-e2e PRIVATE bbs)

add_executable(bbs-test-e2e-bench ${e2e-tests})
target_link_libraries(bbs-test-e2e-bench PRIVATE bbs)
target_compile_definitions(bbs-test-e2e-bench PUBLIC ENABLE_BENCHMARK)

set(fixture-test-list ${fixture-tests})
remove(fixture-test-list bbs-test-fixtures.c)

set(e2e-test-list ${e2e-tests})
remove(e2e-test-list bbs-test-e2e.c)

foreach(test ${fixture-test-list})
	get_filename_component (TName ${test} NAME_WE)
	add_test(
		NAME ${TName}
		COMMAND bbs-test-fixtures ${TName}
		)
endforeach()

foreach(test ${e2e-test-list})
	get_filename_component (TName ${test} NAME_WE)
	add_test(
		NAME ${TName}
		COMMAND bbs-test-e2e ${TName}
		)
endforeach()

