return {
    format_version = 1,
    service_id = "lua-worker",
    application_id = "lua-worker",
    startup = "automatic",
    restart = "on-failure",
    health_check = "ipc-readiness",
    entrypoint = "main.lua",
    requested_capabilities = {"service.background"},
    ipc_endpoints = {"lua-worker"},
    max_message_bytes = 8192,
}
