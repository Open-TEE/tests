import qbs

Project {
    name: "tests"
    references: [
        "clients/clients.qbs",
        "internal_api/storage_test.qbs",
        "internal_api/crypto_test.qbs"
    ]
}


