hyber.log.info("Lua worker started")
hyber.service.ready()
while hyber.service.wait(1000) do
    -- Bounded background work belongs here. No host I/O is available.
end
