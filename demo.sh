#!/bin/bash
# HyberKOS Shell — Demo Test Script
# This script tests the shell automatically.
# Usage: bash demo.sh

BINARY="./target/debug/hyber-shell"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║        HyberKOS Shell v0.12 — Demo & Test Runner            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Send sequential commands to the shell
$BINARY << 'HYBER_SESSION'
help

pwd
ls
tree /

mkdir /runtime/test
touch /runtime/test/hello.txt
ls /runtime

look /runtime/test/hello.txt

meta set /runtime/test/hello.txt app.author string "neo"
meta set /runtime/test/hello.txt app.version int 1
meta ls /runtime/test/hello.txt

acquire /runtime/test/hello.txt rw
handles
release 1

ps
lsdev
lssvc

mnts
rights /runtime

lua hyber.log.info("Hello HyberKOS Lua Runtime!")
lua print("Process ID: " .. hyber.proc.pid())
lua print("User ID:    " .. hyber.proc.uid())
lua print("Namespace exists '/runtime':", hyber.ns.exists("/runtime"))

lua "local entries = hyber.ns.list('/'); for _, e in ipairs(entries) do print('  -> ' .. e.name .. ' [obj:' .. e.obj_id .. ']') end"

lua "local info = hyber.obj.info('/runtime'); print('runtime type=' .. info.type .. ' refs=' .. info.references)"

lua hyber.obj.meta_set("/runtime/test/hello.txt", "lua.note", "string", "written_from_lua")
meta get /runtime/test/hello.txt lua.note

cat /devices/null

su 1000 1000
ps

su 0 0
exit
HYBER_SESSION

echo ""
echo "✅ Demo completed."
