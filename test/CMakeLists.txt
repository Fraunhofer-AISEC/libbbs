# Test source files
set(BBS_FIX_TESTS
    bbs_fix_hash_to_scalar.c
    bbs_fix_generators.c
    bbs_fix_keygen.c
    bbs_fix_sign.c
    bbs_fix_verify.c
    bbs_fix_proof_gen.c
    bbs_fix_proof_verify.c)
set(BBS_E2E_TESTS bbs_e2e_sign_n_proof.c)
set(BBS_BENCH_TESTS bbs_bench_individual.c)

# Generate driver source files
create_test_sourcelist(fix_driver   bbs_fix_driver.c   ${BBS_FIX_TESTS})
create_test_sourcelist(e2e_driver   bbs_e2e_driver.c   ${BBS_E2E_TESTS})
create_test_sourcelist(bench_driver bbs_bench_driver.c ${BBS_BENCH_TESTS})

# Compile generic sources
add_library(bbs_fix_sources   OBJECT ${fix_driver})
add_library(bbs_e2e_sources   OBJECT ${e2e_driver})
add_library(bbs_bench_sources OBJECT ${bench_driver})
target_include_directories(bbs_fix_sources   PUBLIC ../include ../src)
target_include_directories(bbs_e2e_sources   PUBLIC ../include)
target_include_directories(bbs_bench_sources PUBLIC ../include)


# For each ciphersuite, generate fixtures and compile them
set(BBS_CIPHERSUITES bls12-381-sha-256 bls12-381-shake-256)
add_executable(fixtures_transpiler fixtures_transpiler.c)
foreach(suite IN LISTS BBS_CIPHERSUITES)
	add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/fixtures_${suite}.c"
		COMMAND $<TARGET_FILE:fixtures_transpiler> "${suite}" "${CMAKE_CURRENT_SOURCE_DIR}"
		DEPENDS fixtures_transpiler)
	add_library(bbs_fixtures_file_${suite} OBJECT "${CMAKE_CURRENT_BINARY_DIR}/fixtures_${suite}.c")
	target_include_directories(bbs_fixtures_file_${suite} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
endforeach()

# Finally, link each kind of testfile against each ciphersuite file
foreach(suite IN LISTS BBS_CIPHERSUITES)
	# Fixture tests
	add_executable(bbs-fix-${suite} $<TARGET_OBJECTS:bbs_fix_sources>
		$<TARGET_OBJECTS:bbs_fixtures_file_${suite}>)
	target_link_libraries(bbs-fix-${suite} PRIVATE bbs_FIXTURES_ONLY)
	foreach(test ${BBS_FIX_TESTS})
		get_filename_component(TName ${test} NAME_WE)
		add_test(NAME ${TName}_${suite} COMMAND bbs-fix-${suite} ${TName})
	endforeach()

	# End-to-end tests
	add_executable(bbs-e2e-${suite} $<TARGET_OBJECTS:bbs_e2e_sources>
		$<TARGET_OBJECTS:bbs_fixtures_file_${suite}>)
	target_link_libraries(bbs-e2e-${suite} PRIVATE bbs)
	foreach(test ${BBS_E2E_TESTS})
		get_filename_component(TName ${test} NAME_WE)
		add_test(NAME ${TName}_${suite} COMMAND bbs-e2e-${suite} ${TName})
	endforeach()

	# Benchmarks
	add_executable(bbs-bench-${suite} $<TARGET_OBJECTS:bbs_bench_sources>
		$<TARGET_OBJECTS:bbs_fixtures_file_${suite}>)
	target_link_libraries(bbs-bench-${suite} PRIVATE bbs)
endforeach()

# Benchmark command
add_custom_target(bench
	COMMAND bbs-bench-bls12-381-shake-256 bbs_bench_individual
	COMMAND bbs-bench-bls12-381-sha-256   bbs_bench_individual)

