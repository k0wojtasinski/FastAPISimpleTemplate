#!/bin/bash

if [[ "$1" == "debug" ]]; then
    uvicorn server:app --host $BACKEND_HOST --port $BACKEND_PORT --reload
else
    uvicorn server:app --host $BACKEND_HOST --port $BACKEND_PORT
fi