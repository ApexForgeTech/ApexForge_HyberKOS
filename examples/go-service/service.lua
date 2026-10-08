return {
    format_version = 1,
    service_id = "go-worker",
    application_id = "go-worker",
    startup = "automatic",
    restart = "on-failure",
    health_check = "ipc-readiness",
    entrypoint = "main",
    requested_capabilities = {"service.background"},
    ipc_endpoints = {"go-worker"},
    max_message_bytes = 8192,
    max_concurrency = 2,
    arguments = {},
}
