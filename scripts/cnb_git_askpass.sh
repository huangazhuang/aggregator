#!/bin/sh

case "$1" in
  *Username*) printf '%s' "${CNB_TOKEN_USER_NAME:-cnb}" ;;
  *Password*) printf '%s' "${CNB_TOKEN}" ;;
esac
