#!/bin/sh

go run main.go middlewares.go helpers.go #2>> ./logs/errors.log

echo "Server running. See logs."
