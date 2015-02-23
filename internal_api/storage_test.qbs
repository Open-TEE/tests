import qbs

CppApplication {
    name: "storage_test"
    type: "application"

    Depends { name: "InternalApi" }
    Depends { name: "OpenSSL" }

    destinationDirectory: '.'

    files: ["storage_test.c",
	   		"../../emulator/manager/opentee_manager_storage_api.c",
			"../../emulator/manager/storage_key_apis_external_funcs.c"
    		]
}
